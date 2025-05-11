use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;

use clap::Parser;
use regex::Regex;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input packet capture file
    #[arg(short, long)]
    input: PathBuf,

    /// Output file for filtered packets
    #[arg(short, long)]
    output: PathBuf,

    /// Connection handle to filter (optional)
    #[arg(short = 'c', long)]
    handle: Option<String>,
    
    /// Process only write requests, even when no notifications are present
    #[arg(short = 'w', long)]
    write_only: bool,
}

#[derive(Debug, Clone)]
struct BlePacket {
    timestamp: String,
    packet_type: String,
    handle: String,
    description: String,
    raw_line: String, // Store the entire line for debugging
}

// Function to identify the command type based on write request value
fn get_command_label(write_value: &str) -> String {
    // Extract the first few bytes which typically contain the command code
    let parts: Vec<&str> = write_value.split_whitespace().collect();
    if parts.is_empty() {
        return "Unknown".to_string();
    }
    
    // Extract the handle (first 4 chars) and command code
    if parts[0].len() >= 4 {
        let handle = &parts[0][0..4];
        
        // Handle common command types
        match handle {
            "00C0" => {
                if parts.len() > 1 {
                    match parts[1] {
                        "0100" => return "Read Device Info".to_string(),
                        "0000" => return "Reset/Init Device".to_string(),
                        "0003" => return "Read Serial Number".to_string(),
                        "0104" => return "Read Device Status".to_string(),
                        "0020" => return "Read Battery Level".to_string(),
                        "0120" => return "Read Firmware Version".to_string(),
                        "0220" => return "Read Temperature".to_string(),
                        "0300" => return "Read Error Status".to_string(),
                        "0305" => return "Read Memory Map".to_string(),
                        "0301" => return "Read System Status".to_string(),
                        "0501" => if parts.len() > 2 && parts[2] == "0100" {
                            "Enable Feature".to_string()
                        } else if parts.len() > 2 && parts[2] == "0000" {
                            "Disable Feature".to_string()
                        } else if parts.len() > 2 && parts[2] == "0200" {
                            "Set Feature Mode".to_string()
                        } else {
                            "Configure Feature".to_string()
                        },
                        "0406" => return "Read Configuration".to_string(),
                        "0722" => return "Read Device Settings".to_string(),
                        _ => if parts[1].starts_with("10") {
                            "Advanced Command".to_string()
                        } else {
                            format!("C0 Command: {}", parts[1])
                        }
                    }
                } else {
                    "Device Command".to_string()
                }
            },
            "00C9" => {
                if parts.len() > 1 {
                    match parts[1] {
                        "0100" => return "Read Secondary Info".to_string(),
                        "0000" => return "Reset Secondary".to_string(),
                        "0003" => return "Read Secondary Serial".to_string(),
                        "0104" => return "Read Secondary Status".to_string(),
                        "0020" => return "Read Secondary Battery".to_string(),
                        "0220" => return "Read Secondary Temperature".to_string(),
                        "0300" => return "Read Secondary Errors".to_string(),
                        "0501" => if parts.len() > 2 && parts[2] == "0000" {
                            "Disable Secondary Feature".to_string()
                        } else if parts.len() > 2 && parts[2] == "0200" {
                            "Set Secondary Mode".to_string()
                        } else {
                            "Configure Secondary".to_string()
                        },
                        "0724" => return "Configure Secondary Device".to_string(),
                        "0704" => return "Set Secondary Parameter".to_string(),
                        _ => if parts[1].starts_with("10") {
                            "Secondary Advanced Command".to_string()
                        } else {
                            format!("C9 Command: {}", parts[1])
                        }
                    }
                } else {
                    "Secondary Command".to_string()
                }
            },
            "00D2" => {
                if parts.len() > 1 {
                    match parts[1] {
                        "0100" => return "Read Tertiary Info".to_string(),
                        "0000" => return "Reset Tertiary Device".to_string(),
                        "0522" => return "Set Tertiary Parameter".to_string(),
                        _ => format!("D2 Command: {}", parts[1])
                    }
                } else {
                    "Tertiary Command".to_string()
                }
            },
            _ => format!("Handle: {}", handle)
        }
    } else {
        "Unknown Command".to_string()
    }
}

fn parse_packet_line(line: &str) -> Option<BlePacket> {
    // Example line format:
    // May 10 22:08:45.756  ATT Send         0x0054  C0:6A:04:5C:16:AE  Write Request - Handle:0x0017 - Value: 00C0 1002 0002 B9A5
    
    let parts: Vec<&str> = line.split("  ").filter(|s| !s.is_empty()).collect();
    if parts.len() < 4 {
        return None;
    }

    let timestamp = parts[0].trim().to_string();
    let packet_type = parts[1].trim().to_string();
    let handle = parts[2].trim().to_string();
    let description = parts[3..].join("  ").trim().to_string();
    
    Some(BlePacket {
        timestamp,
        packet_type,
        handle,
        description,
        raw_line: line.to_string(),
    })
}

fn is_write_request(packet: &BlePacket) -> bool {
    packet.packet_type.contains("ATT Send") && packet.description.contains("Write Request")
}

fn is_notification(packet: &BlePacket) -> bool {
    packet.packet_type.contains("ATT Receive") && packet.description.contains("Handle Value Notification")
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    
    println!("Starting to process Bluetooth packet capture file: {:?}", args.input);

    let file = match File::open(&args.input) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error opening input file: {}", e);
            return Err(e);
        }
    };
    let reader = BufReader::new(file);

    // Store the output path as a string before moving the PathBuf
    let output_path = args.output.to_string_lossy().to_string();
    
    let mut output_file = match OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&args.output) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Error creating output file: {}", e);
                return Err(e);
            }
        };

    // Store the most recent write request seen
    let mut last_write_request: Option<BlePacket> = None;
    
    // Counters for statistics
    let mut write_request_count = 0;
    let mut notification_count = 0;
    let mut pairs_found = 0;
    let mut write_only_count = 0;

    // Write header to output file in a more readable vertical format
    writeln!(output_file, "Bluetooth Request-Notification Pairs")?;
    writeln!(output_file, "====================================\n")?;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Error reading line: {}", e);
                continue;
            }
        };
        
        if let Some(packet) = parse_packet_line(&line) {
            // Filter by connection handle if specified
            if let Some(filter_handle) = &args.handle {
                if !packet.handle.contains(filter_handle) {
                    continue;
                }
            }

            if is_write_request(&packet) {
                write_request_count += 1;
                // Debug output
                println!("Found Write Request: {}", packet.description);
                
                // If we're in write_only mode and have a previous write request that hasn't been paired,
                // process it now before storing the new one
                if args.write_only && last_write_request.is_some() {
                    let write_packet = last_write_request.as_ref().unwrap();
                    write_only_count += 1;
                    
                    // Extract values
                    let write_value = extract_write_value(&write_packet.description).unwrap_or_default();
                    
                    // Get command label
                    let command_label = get_command_label(&write_value);
                    
                    // Write the request to output file
                    writeln!(output_file, "Timestamp: {}", write_packet.timestamp)?;
                    writeln!(output_file, "Command Type: {}", command_label)?;
                    writeln!(output_file, "Write Request:")?;
                    writeln!(output_file, "  {}", write_value)?;
                    writeln!(output_file)?; // Add empty line
                }
                
                // Save this write request
                last_write_request = Some(packet);
            } else if is_notification(&packet) {
                notification_count += 1;
                // Debug output
                println!("Found Notification: {}", packet.description);
                
                // If we have a recent write request, pair it with this notification
                if let Some(write_packet) = &last_write_request {
                    pairs_found += 1;
                    
                    // Extract values
                    let write_value = extract_write_value(&write_packet.description).unwrap_or_default();
                    let notification_value = extract_notification_value(&packet.description).unwrap_or_default();
                    
                    // Get command label
                    let command_label = get_command_label(&write_value);
                    
                    // Write the pair to output file in a more readable vertical format
                    writeln!(output_file, "Timestamp: {}", packet.timestamp)?;
                    writeln!(output_file, "Command Type: {}", command_label)?;
                    writeln!(output_file, "Write Request:")?;
                    writeln!(output_file, "  {}", write_value)?;
                    writeln!(output_file, "Notification:")?;
                    writeln!(output_file, "  {}", notification_value)?;
                    writeln!(output_file)?; // Add empty line between pairs
                    
                    // Reset write request after we've paired it
                    last_write_request = None;
                }
            } else if args.write_only && packet.description.contains("Write Response") {
                // In write_only mode, consider Write Response as a signal to process the last write request
                if let Some(write_packet) = &last_write_request {
                    write_only_count += 1;
                    
                    // Extract values
                    let write_value = extract_write_value(&write_packet.description).unwrap_or_default();
                    
                    // Get command label
                    let command_label = get_command_label(&write_value);
                    
                    // Write the request to output file
                    writeln!(output_file, "Timestamp: {}", write_packet.timestamp)?;
                    writeln!(output_file, "Command Type: {}", command_label)?;
                    writeln!(output_file, "Write Request:")?;
                    writeln!(output_file, "  {}", write_value)?;
                    writeln!(output_file)?; // Add empty line
                    
                    // Reset write request
                    last_write_request = None;
                }
            }
        }
    }

    // Process any remaining write request in write_only mode
    if args.write_only && last_write_request.is_some() {
        let write_packet = last_write_request.as_ref().unwrap();
        write_only_count += 1;
        
        // Extract values
        let write_value = extract_write_value(&write_packet.description).unwrap_or_default();
        
        // Get command label
        let command_label = get_command_label(&write_value);
        
        // Write the request to output file
        writeln!(output_file, "Timestamp: {}", write_packet.timestamp)?;
        writeln!(output_file, "Command Type: {}", command_label)?;
        writeln!(output_file, "Write Request:")?;
        writeln!(output_file, "  {}", write_value)?;
        writeln!(output_file)?; // Add empty line
    }

    println!("Processing complete. Statistics:");
    println!("  Write Requests found: {}", write_request_count);
    println!("  Notifications found: {}", notification_count);
    if args.write_only {
        println!("  Write-only entries processed: {}", write_only_count);
    } else {
        println!("  Pairs matched: {}", pairs_found);
    }
    println!("Results written to: {}", output_path);
    
    Ok(())
}

fn extract_write_value(description: &str) -> Option<String> {
    // Extract the value part after "Value:"
    let re = Regex::new(r"Value:\s*(.+)").ok()?;
    re.captures(description)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

fn extract_notification_value(description: &str) -> Option<String> {
    // Extract the value part from notifications
    let re = Regex::new(r"Value:\s*(.+)").ok()?;
    re.captures(description)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}
