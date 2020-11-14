use futures::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::*;
use web_sys::{
    UsbAlternateInterface, UsbConfiguration, UsbDevice, UsbDirection, UsbEndpoint, UsbInterface,
};

macro_rules! console_log {
    // Note that this is using the `log` function imported above during
    // `bare_bones`
    ($($t:tt)*) => (web_sys::console::log_1(&format_args!($($t)*).to_string().into()))
}

mod adb;
mod signer;

pub fn log_jsobj(obj: &JsValue) {
    web_sys::console::log_1(obj);
}

// Called when the wasm module is instantiated
#[wasm_bindgen(start)]
pub fn main() -> Result<(), JsValue> {
    // Use `web_sys`'s global `window` function to get a handle on the global
    // window object.
    let window = web_sys::window().expect("no global `window` exists");
    let document = window.document().expect("should have a document on window");
    let body = document.body().expect("document should have a body");

    // Manufacture the element we're gonna append
    let val = document
        .create_element("p")?
        .dyn_into::<web_sys::HtmlElement>()?;
    val.set_inner_html("Hello from Rust!");

    let cl = Closure::wrap(Box::new(move || {
        spawn_local(usb_start().map(|r| {
            r.unwrap_or_else(|e| {
                log_jsobj(&e);
                console_log!("USB selection cancelled");
                console_log!("See chrome://device-log/ if this error is not intentional");
            })
        }));
    }) as Box<dyn FnMut()>);

    val.set_onclick(Some(cl.as_ref().unchecked_ref()));
    cl.forget();

    body.append_child(&val)?;
    Ok(())
}

async fn usb_start() -> Result<(), JsValue> {
    let window = web_sys::window().expect("no global `window` exists");
    let usb = window.navigator().usb();
    let options = web_sys::UsbDeviceRequestOptions::new(&js_sys::Array::new());
    let device = JsFuture::from(usb.request_device(&options))
        .await?
        .dyn_into::<UsbDevice>()?;
    log_jsobj(&device);

    /*
    // register close event
    let device_close = device.clone();
    let on_close = Closure::wrap(Box::new(move || {
        console_log!("Cloding USB Device.");
        spawn_local(JsFuture::from(device_close.close()).map(|_| ()));
    }) as Box<dyn FnMut()>);
    window.set_onunload(Some(on_close.as_ref().unchecked_ref()));
    on_close.forget();
    */

    // Let us retrieve the configuration value
    let (config, interface, alt_interface) =
        find_adb_config(&device).ok_or("No configuration is found")?;
    let configuration_value = config.configuration_value();
    let endpoints = find_endpoints(&alt_interface).ok_or("No endpoints found")?;
    JsFuture::from(device.open()).await?;
    JsFuture::from(device.select_configuration(configuration_value)).await?;
    JsFuture::from(device.claim_interface(interface.interface_number())).await?;
    let banner = adb::connect(
        &device,
        &endpoints,
        &signer::RsaKey::from_pkcs8(signer::DEFAULT_PRIV_KEY).map_err(|e| format!("{}", e))?,
    )
    .await?;
    console_log!("Banner received: {}", String::from_utf8_lossy(&banner));
    Ok(())
}

fn find_adb_config(
    device: &UsbDevice,
) -> Option<(UsbConfiguration, UsbInterface, UsbAlternateInterface)> {
    const CLASS: u8 = 0xFF;
    const SUBCLASS: u8 = 0x42;
    const PROTOCOL: u8 = 0x01;
    for configuration in device.configurations().iter() {
        let configuration = configuration.dyn_into::<UsbConfiguration>().unwrap();
        for interface in configuration.interfaces().iter() {
            let interface = interface.dyn_into::<UsbInterface>().unwrap();
            for alt_interface in interface.alternates().iter() {
                let alt_interface = alt_interface.dyn_into::<UsbAlternateInterface>().unwrap();

                if alt_interface.interface_class() == CLASS
                    && alt_interface.interface_subclass() == SUBCLASS
                    && alt_interface.interface_protocol() == PROTOCOL
                {
                    return Some((configuration, interface, alt_interface));
                }
            }
        }
    }
    None
}

pub struct Endpoints {
    n_in: u8,
    n_out: u8,
    packet_size_in: u32,
}

fn find_endpoints(alt_interface: &UsbAlternateInterface) -> Option<Endpoints> {
    let endpoints = alt_interface.endpoints();
    if endpoints.length() != 2 {
        None
    } else {
        let end1 = endpoints.get(0).dyn_into::<UsbEndpoint>().unwrap();
        let end2 = endpoints.get(1).dyn_into::<UsbEndpoint>().unwrap();

        if end1.direction() == UsbDirection::In && end2.direction() == UsbDirection::Out {
            Some(Endpoints {
                n_in: end1.endpoint_number(),
                n_out: end2.endpoint_number(),
                packet_size_in: end1.packet_size(),
            })
        } else if end1.direction() == UsbDirection::Out && end2.direction() == UsbDirection::In {
            Some(Endpoints {
                n_in: end2.endpoint_number(),
                n_out: end1.endpoint_number(),
                packet_size_in: end2.packet_size(),
            })
        } else {
            None
        }
    }
}
