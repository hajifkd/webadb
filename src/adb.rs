use crate::Endpoints;
use byteorder::{LittleEndian, WriteBytesExt};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::*;
use web_sys::UsbDevice;

#[repr(u32)]
#[derive(Copy, Debug, Clone)]
pub enum AdbCommand {
    Sync = 0x434e5953,
    Cnxn = 0x4e584e43,
    Auth = 0x48545541,
    Open = 0x4e45504f,
    Okay = 0x59414b4f,
    Clse = 0x45534c43,
    Wrte = 0x45545257,
    // [b'SYNC', b'CNXN', b'AUTH', b'OPEN', b'OKAY', b'CLSE', b'WRTE']
}

const MAX_ADB_DATA: u32 = 4096;
const VERSION: u32 = 0x01000000;

#[derive(Debug, Clone)]
struct AdbMessage {
    command: AdbCommand,
    arg0: u32,
    arg1: u32,
    data: Vec<u8>,
}

// TODO implements commands according to https://github.com/google/python-adb/blob/40ffe13448857df6d2ce34450f4a68234ade5b87/adb/adb_protocol.py
impl AdbMessage {
    pub fn new(command: AdbCommand, arg0: u32, arg1: u32, data: Vec<u8>) -> Self {
        AdbMessage {
            command,
            arg0,
            arg1,
            data,
        }
    }

    fn magic(&self) -> u32 {
        (self.command as u32) ^ 0xFF_FF_FF_FF
    }

    fn checksum(&self) -> u32 {
        self.data.iter().fold(0u32, |acc, x| acc + *x as u32) & 0xFF_FF_FF_FF
    }

    fn pack(&self) -> Vec<u8> {
        let mut result = vec![];
        result.write_u32::<LittleEndian>(self.command as _).unwrap();
        result.write_u32::<LittleEndian>(self.arg0).unwrap();
        result.write_u32::<LittleEndian>(self.arg1).unwrap();
        result
            .write_u32::<LittleEndian>(self.data.len() as _)
            .unwrap();
        result.write_u32::<LittleEndian>(self.checksum()).unwrap();
        result.write_u32::<LittleEndian>(self.magic()).unwrap();
        result
    }

    pub async fn send(self, usb: &UsbDevice, endpoints: &Endpoints) -> Result<JsValue, JsValue> {
        let mut s = self;
        JsFuture::from(usb.transfer_out_with_u8_array(endpoints.n_out, &mut s.pack())).await?;
        JsFuture::from(usb.transfer_out_with_u8_array(endpoints.n_out, &mut s.data)).await
    }
}

pub async fn connect(usb: &UsbDevice, endpoints: &Endpoints) -> Result<JsValue, JsValue> {
    let message = AdbMessage::new(
        AdbCommand::Cnxn,
        VERSION,
        MAX_ADB_DATA,
        b"host::webadb\0".to_vec(),
    );
    message.send(usb, endpoints).await
}
