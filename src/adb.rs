use crate::{signer, Endpoints};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use derive_try_from_primitive::TryFromPrimitive;
use js_sys::Uint8Array;
use std::convert::TryFrom;
use std::io::Cursor;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::*;
use web_sys::{UsbDevice, UsbInTransferResult};

#[derive(TryFromPrimitive)]
#[repr(u32)]
#[derive(Copy, Debug, Clone, PartialEq, Eq)]
pub enum AdbCommandKind {
    Sync = 0x434e5953,
    Cnxn = 0x4e584e43,
    Auth = 0x48545541,
    Open = 0x4e45504f,
    Okay = 0x59414b4f,
    Clse = 0x45534c43,
    Wrte = 0x45545257,
    // [b'SYNC', b'CNXN', b'AUTH', b'OPEN', b'OKAY', b'CLSE', b'WRTE']
}

#[derive(Debug, Clone)]
struct AdbCommand {
    command_kind: AdbCommandKind,
    arg0: u32,
    arg1: u32,
}

impl AdbCommand {
    const COMMAND_LENGTH: usize = 24;
    fn new(command_kind: AdbCommandKind, arg0: u32, arg1: u32) -> Self {
        AdbCommand {
            command_kind,
            arg0,
            arg1,
        }
    }

    fn magic(&self) -> u32 {
        (self.command_kind as u32) ^ 0xFF_FF_FF_FF
    }

    fn unpack(data: &[u8]) -> Result<(Self, u32, u32), String> {
        if data.len() != AdbCommand::COMMAND_LENGTH {
            Err(format!(
                "Data size is wrong: {} octets expected, {} octets received",
                AdbCommand::COMMAND_LENGTH,
                data.len()
            ))
        } else {
            let mut reader = Cursor::new(data);
            let result = AdbCommand {
                command_kind: AdbCommandKind::try_from(reader.read_u32::<LittleEndian>().unwrap())
                    .map_err(|n| format!("Invalid ADB command kind {:x}", n))?,
                arg0: reader.read_u32::<LittleEndian>().unwrap(),
                arg1: reader.read_u32::<LittleEndian>().unwrap(),
            };
            let len = reader.read_u32::<LittleEndian>().unwrap();
            let checksum = reader.read_u32::<LittleEndian>().unwrap();
            let magic = reader.read_u32::<LittleEndian>().unwrap();
            if magic == result.magic() {
                Ok((result, len, checksum))
            } else {
                Err("Invalid magic".to_owned())
            }
        }
    }
}

const MAX_ADB_DATA: u32 = 4096;
const VERSION: u32 = 0x01000000;

#[derive(Debug, Clone)]
struct AdbMessage {
    command: AdbCommand,
    data: Vec<u8>,
}

// TODO implements commands according to https://github.com/google/python-adb/blob/40ffe13448857df6d2ce34450f4a68234ade5b87/adb/adb_protocol.py
impl AdbMessage {
    pub fn new(command: AdbCommand, data: Vec<u8>) -> Self {
        AdbMessage { command, data }
    }

    fn checksum(&self) -> u32 {
        self.data.iter().fold(0u32, |acc, x| acc + *x as u32) & 0xFF_FF_FF_FF
    }

    fn pack(&self) -> Vec<u8> {
        let mut result = vec![];
        result
            .write_u32::<LittleEndian>(self.command.command_kind as _)
            .unwrap();
        result.write_u32::<LittleEndian>(self.command.arg0).unwrap();
        result.write_u32::<LittleEndian>(self.command.arg1).unwrap();
        result
            .write_u32::<LittleEndian>(self.data.len() as _)
            .unwrap();
        result.write_u32::<LittleEndian>(self.checksum()).unwrap();
        result
            .write_u32::<LittleEndian>(self.command.magic())
            .unwrap();
        result
    }
}

async fn send_message(
    s: AdbMessage,
    usb: &UsbDevice,
    endpoints: &Endpoints,
) -> Result<JsValue, JsValue> {
    let mut s = s;
    JsFuture::from(usb.transfer_out_with_u8_array(endpoints.n_out, &mut s.pack())).await?;
    JsFuture::from(usb.transfer_out_with_u8_array(endpoints.n_out, &mut s.data)).await
}

async fn recv(usb: &UsbDevice, endpoints: &Endpoints, len: u32) -> Result<Vec<u8>, JsValue> {
    let transfer_result = JsFuture::from(usb.transfer_in(endpoints.n_in, len))
        .await?
        .dyn_into::<UsbInTransferResult>()?;
    let data = transfer_result.data().ok_or(transfer_result.status())?;
    Ok(Uint8Array::new(&data.buffer()).to_vec())
}

async fn recv_message(usb: &UsbDevice, endpoints: &Endpoints) -> Result<AdbMessage, JsValue> {
    let command_data = recv(&usb, &endpoints, AdbCommand::COMMAND_LENGTH as _).await?;
    let (command, len, checksum) = AdbCommand::unpack(&command_data)?;
    let data = recv(&usb, &endpoints, len).await?;
    let message = AdbMessage::new(command, data);

    if message.checksum() != checksum {
        Err("Invalid checksum".into())
    } else {
        Ok(message)
    }
}

const AUTH_TOKEN: u32 = 1;
const AUTH_SIGNATURE: u32 = 2;
const AUTH_RSAPUBLICKEY: u32 = 3;

pub async fn connect(
    usb: &UsbDevice,
    endpoints: &Endpoints,
    key: &signer::RsaKey,
) -> Result<Vec<u8>, JsValue> {
    let message = AdbMessage::new(
        AdbCommand::new(AdbCommandKind::Cnxn, VERSION, MAX_ADB_DATA),
        b"host::webadb\0".to_vec(),
    );
    send_message(message, usb, endpoints).await?;
    let resp = recv_message(&usb, &endpoints).await?;

    match resp.command.command_kind {
        AdbCommandKind::Auth => {
            if resp.command.arg0 != AUTH_TOKEN {
                return Err(format!(
                    "Invalid response received during AUTH: {}",
                    resp.command.arg0
                )
                .into());
            }
            console_log!("Auth message received; token is {:?}", &resp.data);

            // check key
            let sign = key.sign(&resp.data).map_err(|e| format!("{}", e))?;
            console_log!("Signature is {:?}", &sign);
            let auth_try = AdbMessage::new(
                AdbCommand::new(AdbCommandKind::Auth, AUTH_SIGNATURE, 0),
                sign,
            );
            send_message(auth_try, usb, endpoints).await?;
            let resp_try = recv_message(&usb, &endpoints).await?;
            if resp_try.command.command_kind == AdbCommandKind::Cnxn {
                console_log!("The key had been accepted.");
                // if registered, return.
                return Ok(resp_try.data);
            } else {
                console_log!("{:?}", resp_try.command.command_kind);
            }

            console_log!("The key has never been accepted. Ask the permission.");
            let mut pubkey = key
                .encoded_public_key()
                .map_err(|e| format!("{}", e))?
                .into_bytes();
            pubkey.push(b'\0');
            let message = AdbMessage::new(
                AdbCommand::new(AdbCommandKind::Auth, AUTH_RSAPUBLICKEY, 0),
                pubkey,
            );
            send_message(message, usb, endpoints).await?;
            let resp_hc = recv_message(&usb, &endpoints).await?;
            if resp_hc.command.command_kind == AdbCommandKind::Cnxn {
                Ok(resp_hc.data)
            } else {
                Err(format!(
                    "Received invalid ADB command after AUTH: {:?}",
                    resp_hc.command.command_kind
                )
                .into())
            }
        }
        AdbCommandKind::Cnxn => Ok(resp.data),
        _ => Err(format!(
            "Received invalid ADB command: {:?}",
            resp.command.command_kind
        )
        .into()),
    }
}
