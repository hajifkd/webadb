extern crate web_sys;

use futures::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::*;

macro_rules! console_log {
    // Note that this is using the `log` function imported above during
    // `bare_bones`
    ($($t:tt)*) => (web_sys::console::log_1(&format_args!($($t)*).to_string().into()))
}

fn log_jsobj(obj: &JsValue) {
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
            })
        }));
    }) as Box<dyn FnMut()>);

    val.set_onclick(Some(cl.as_ref().unchecked_ref()));
    cl.forget();

    console_log!("aaaaaa");

    body.append_child(&val)?;
    Ok(())
}

async fn usb_start() -> Result<(), JsValue> {
    let window = web_sys::window().expect("no global `window` exists");
    let usb = window.navigator().usb();
    let options = web_sys::UsbDeviceRequestOptions::new(&js_sys::Array::new());
    let device = JsFuture::from(usb.request_device(&options))
        .await?
        .dyn_into::<web_sys::UsbDevice>()?;
    log_jsobj(&device);
    // Let us retrieve the configuration value
    let config = device.configuration().ok_or("No configuration is found")?;
    let configuration_value = config.configuration_value();
    JsFuture::from(device.open()).await?;
    JsFuture::from(device.select_configuration(configuration_value)).await?;
    Ok(())
}
