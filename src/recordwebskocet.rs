use std::env;
use std::net::ToSocketAddrs;
use ipgeolocate::{Locator, Service};
use reqwest::blocking::get;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct IpInfo {
    ip: String,
    country: String,
    city: String,
    region: String,
    latitude: f64,
    longitude: f64,
    isp: String,
    asn: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Użycie: recordwebskocet <IP lub host>");
        return Ok(());
    }
    let target = &args[1];
    
    let ip = match target.to_socket_addrs() {
        Ok(mut addrs) => addrs.next().map(|addr| addr.ip().to_string()).unwrap_or(target.clone()),
        Err(_) => target.clone(),
    };
    
    println!("Analiza lokalizacji serwera dla IP: {}", ip);
    
    let service = Service::IpApi;
    match Locator::get(&ip, service).await {
        Ok(loc) => {
            println!("Kraj: {}", loc.country);
            println!("Miasto: {}", loc.city);
            println!("Region: {}", loc.region);
            println!("Szerokość geogr.: {}", loc.latitude);
            println!("Długość geogr.: {}", loc.longitude);
            println!("Strefa czasowa: {}", loc.timezone);
        }
        Err(e) => println!("Błąd geolokacji: {}", e),
    }
    
    let url = format!("https://ipapi.co/{}/json/", ip);
    let response = get(&url)?.json::<IpInfo>()?;
    println!("ISP: {}", response.isp);
    println!("ASN: {}", response.asn);
    println!("Pełne info: {:?}", response);
    
    Ok(())
}