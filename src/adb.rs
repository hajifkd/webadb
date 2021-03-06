use crate::{signer, Endpoints};
use async_stream::stream;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use derive_try_from_primitive::TryFromPrimitive;
use futures::prelude::*;
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
) -> Result<(), JsValue> {
    let mut s = s;
    JsFuture::from(usb.transfer_out_with_u8_array(endpoints.n_out, &mut s.pack())).await?;
    if s.data.len() != 0 {
        JsFuture::from(usb.transfer_out_with_u8_array(endpoints.n_out, &mut s.data)).await?;
    }
    Ok(())
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
    let data = if len > 0 {
        recv(&usb, &endpoints, len).await?
    } else {
        vec![]
    };
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

#[derive(Clone)]
pub struct AdbSession {
    banner: Vec<u8>,
    usb: UsbDevice,
    endpoints: Endpoints,
}

/// Establishes a new connection and returns the banner of the target
async fn connect(
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

            // check key
            let sign = key.sign(&resp.data).map_err(|e| format!("{}", e))?;
            let auth_try = AdbMessage::new(
                AdbCommand::new(AdbCommandKind::Auth, AUTH_SIGNATURE, 0),
                sign,
            );
            send_message(auth_try, usb, endpoints).await?;
            let resp_try = recv_message(&usb, &endpoints).await?;
            if resp_try.command.command_kind == AdbCommandKind::Cnxn {
                console_println!("The key had been accepted.");
                // if registered, return.
                return Ok(resp_try.data);
            } else {
                console_println!("{:?}", resp_try.command.command_kind);
            }

            console_println!("The key has never been accepted. Ask the permission.");
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

impl AdbSession {
    pub async fn open(
        usb: UsbDevice,
        endpoints: Endpoints,
        key: &signer::RsaKey,
    ) -> Result<Self, JsValue> {
        Ok(AdbSession {
            banner: connect(&usb, &endpoints, &key).await?,
            usb,
            endpoints,
        })
    }

    pub fn banner<'a>(&'a self) -> std::borrow::Cow<'a, str> {
        String::from_utf8_lossy(&self.banner)
    }

    pub async fn new_connection(
        &self,
        destination: &Destination,
    ) -> Result<AdbConnection, JsValue> {
        AdbConnection::open(&self.usb, &self.endpoints, &destination).await
    }

    // TODO doesnt work
    pub async fn new_shell_connection(&self) -> Result<AdbShellConnection, JsValue> {
        Ok(AdbShellConnection {
            conn: AdbConnection::open(
                &self.usb,
                &self.endpoints,
                &Destination::new("shell".as_bytes().to_owned(), None),
            )
            .await?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Destination {
    destination: Vec<u8>,
    args: Option<Vec<u8>>,
}

impl Destination {
    pub fn new(destination: Vec<u8>, args: Option<Vec<u8>>) -> Self {
        Self { destination, args }
    }

    pub fn shell(command: &str) -> Self {
        Self::new(b"shell".to_vec(), Some(command.as_bytes().to_owned()))
    }

    fn bytes(&self) -> Vec<u8> {
        let mut result = self.destination.clone();
        result.push(b':');
        if let Some(ref args) = self.args {
            result.extend(args);
        }
        result.push(b'\0');

        result
    }
}

#[derive(Debug, Clone)]
pub struct AdbConnection {
    local_id: u32,
    remote_id: u32,
    usb: UsbDevice,
    endpoints: Endpoints,
}

impl AdbConnection {
    async fn open(
        usb: &UsbDevice,
        endpoints: &Endpoints,
        destination: &Destination,
    ) -> Result<Self, JsValue> {
        let local_id = 1; // const here
        let message = AdbMessage::new(
            AdbCommand::new(AdbCommandKind::Open, local_id, 0),
            destination.bytes(),
        );

        send_message(message, usb, endpoints).await?;
        let mut message = recv_message(usb, endpoints).await?;

        if message.command.arg1 != local_id {
            return Err(format!(
                "Expected local id {}, received {}",
                local_id, message.command.arg1
            )
            .into());
        }

        if message.command.command_kind == AdbCommandKind::Clse {
            // read again
            message = recv_message(usb, endpoints).await?;
        }

        if message.command.command_kind == AdbCommandKind::Okay {
            Ok(AdbConnection {
                local_id,
                remote_id: message.command.arg0,
                usb: usb.clone(),
                endpoints: endpoints.clone(),
            })
        } else {
            Err(format!("Expected OKAY, received {:?}", message.command.command_kind).into())
        }
    }

    async fn write(&self, data: Vec<u8>) -> Result<(), JsValue> {
        send_message(
            AdbMessage::new(
                AdbCommand::new(AdbCommandKind::Wrte, self.local_id, self.remote_id),
                data,
            ),
            &self.usb,
            &self.endpoints,
        )
        .await?;
        let (ack, _) = self.read().await?;

        if ack != AdbCommandKind::Okay {
            Err(format!("Expected OKAY, received {:?}", ack).into())
        } else {
            Ok(())
        }
    }

    async fn send_empty(&self, kind: AdbCommandKind) -> Result<(), JsValue> {
        send_message(
            AdbMessage::new(AdbCommand::new(kind, self.local_id, self.remote_id), vec![]),
            &self.usb,
            &self.endpoints,
        )
        .await
    }

    async fn read(&self) -> Result<(AdbCommandKind, Vec<u8>), JsValue> {
        let data = recv_message(&self.usb, &self.endpoints).await?;

        if data.command.arg0 != 0 && data.command.arg0 != self.remote_id {
            return Err(format!(
                "Expected remote id {}, received {}",
                self.remote_id, data.command.arg0
            )
            .into());
        }

        if data.command.arg1 != 0 && data.command.arg1 != self.local_id {
            return Err(format!(
                "Expected local id {}, received {}; multiple local id is not supported",
                self.local_id, data.command.arg1
            )
            .into());
        }

        if data.command.command_kind == AdbCommandKind::Wrte {
            self.send_empty(AdbCommandKind::Okay).await?;
        } else if data.command.command_kind == AdbCommandKind::Clse {
            self.send_empty(AdbCommandKind::Clse).await?;
        } else {
            return Err(format!(
                "Expected WRTE or CLSE, received {:?}.",
                data.command.command_kind
            )
            .into());
        }

        Ok((data.command.command_kind, data.data))
    }

    pub fn read_stream(&self) -> impl Stream<Item = Result<Vec<u8>, JsValue>> {
        let conn = self.clone();
        stream! {
            loop {
                let data = conn.read().await;

                if let Err(e) = data {
                    yield Err(e);
                    return;
                }

                let (kind, data) = data.unwrap();

                if kind == AdbCommandKind::Clse {
                    let data = conn.send_empty(AdbCommandKind::Clse).await;
                    if let Err(e) = data {
                        yield Err(e);
                    }
                    return;
                }

                yield Ok(data);
            }
        }
    }
}

#[derive(Clone)]
pub struct AdbShellConnection {
    conn: AdbConnection,
}

impl AdbShellConnection {
    pub fn output(&self) -> impl Stream<Item = Result<Vec<u8>, JsValue>> {
        self.conn.read_stream()
    }

    pub async fn exec(self, cmd: String) -> Result<(), JsValue> {
        console_println!("executing {}", cmd);
        let mut cmd = cmd;
        cmd.push_str("\n");
        let cmd = cmd.as_bytes();
        let mut payload = vec![0u8];
        payload.write_u32::<LittleEndian>(cmd.len() as _).unwrap();
        payload.extend(cmd);
        // Needed?
        payload.push(4);
        payload.write_u32::<LittleEndian>(0).unwrap();
        self.conn.write(payload).await?;
        Ok(())
    }
}
