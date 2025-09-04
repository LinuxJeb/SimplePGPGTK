use gtk4::prelude::*;
use gtk4::{glib, Application, ApplicationWindow, Box, Button, Dialog, Entry, Label, ScrolledWindow, TextView, MessageDialog, SearchEntry};
use std::process::Command;
use std::rc::Rc;
use std::cell::RefCell;
use std::env;
use which::which;

const APP_ID: &str = "com.linuxjeb.pgpmgr";

fn main() -> glib::ExitCode {
    let app = Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_ui);
    app.run()
}

fn build_ui(app: &Application) {
    // Create main window
    let window = ApplicationWindow::builder()
        .application(app)
        .title("PGP Manager")
        .default_width(600)
        .default_height(400)
        .build();

    // Create main layout
    let main_box = Box::new(gtk4::Orientation::Vertical, 10);
    main_box.set_margin_top(20);
    main_box.set_margin_bottom(20);
    main_box.set_margin_start(20);
    main_box.set_margin_end(20);

    // Title
    let title = Label::new(Some("Simple PGP Manager"));
    title.set_markup("<span size='large' weight='bold'>PGP Key Manager</span>");
    main_box.append(&title);

    // Create buttons
    let buttons_box = Box::new(gtk4::Orientation::Vertical, 10);
    
    let generate_key_btn = Button::with_label("Generate New PGP Key");
    let import_key_btn = Button::with_label("Import PGP Key");
    let view_keys_btn = Button::with_label("View My Keys");
    let view_priv_keys_btn = Button::with_label("View Private Keys - DO NOT SHARE");

    let encrypt_msg_btn = Button::with_label("Encrypt Message");
    let decrypt_msg_btn = Button::with_label("Decrypt Message");

    buttons_box.append(&generate_key_btn);
    buttons_box.append(&import_key_btn);
    buttons_box.append(&view_keys_btn);
    buttons_box.append(&view_priv_keys_btn);
    buttons_box.append(&encrypt_msg_btn);
    buttons_box.append(&decrypt_msg_btn);

    main_box.append(&buttons_box);
    window.set_child(Some(&main_box));

    // Connect button signals
    let window_clone = window.clone();
    generate_key_btn.connect_clicked(move |_| {
        show_generate_key_dialog(&window_clone);
    });

    let window_clone = window.clone();
    import_key_btn.connect_clicked(move |_| {
        show_import_key_dialog(&window_clone);
    });

    let window_clone = window.clone();
    view_priv_keys_btn.connect_clicked(move |_| {
        show_private_keys_dialog(&window_clone);
    });

    let window_clone = window.clone();
    view_keys_btn.connect_clicked(move |_| {
        show_keys_dialog(&window_clone);
    });

    let window_clone = window.clone();
    encrypt_msg_btn.connect_clicked(move |_| {
        show_encrypt_dialog(&window_clone);
    });

    let window_clone = window.clone();
    decrypt_msg_btn.connect_clicked(move |_| {
        show_decrypt_dialog(&window_clone);
    });

    window.present();
}

fn show_generate_key_dialog(parent: &ApplicationWindow) {
    let dialog = Dialog::builder()
        .title("Generate New PGP Key")
        .transient_for(parent)
        .modal(true)
        .default_width(400)
        .default_height(300)
        .build();

    let content_box = Box::new(gtk4::Orientation::Vertical, 10);
    content_box.set_margin_top(10);
    content_box.set_margin_bottom(10);
    content_box.set_margin_start(10);
    content_box.set_margin_end(10);

    // Form fields
    let name_label = Label::new(Some("Full Name:"));
    name_label.set_halign(gtk4::Align::Start);
    let name_entry = Entry::new();
    
    let email_label = Label::new(Some("Email:"));
    email_label.set_halign(gtk4::Align::Start);
    let email_entry = Entry::new();

    let comment_label = Label::new(Some("Comment (optional):"));
    comment_label.set_halign(gtk4::Align::Start);
    let comment_entry = Entry::new();

    content_box.append(&name_label);
    content_box.append(&name_entry);
    content_box.append(&email_label);
    content_box.append(&email_entry);
    content_box.append(&comment_label);
    content_box.append(&comment_entry);

    // Buttons
    let button_box = Box::new(gtk4::Orientation::Horizontal, 10);
    let generate_btn = Button::with_label("Generate");
    let cancel_btn = Button::with_label("Cancel");

    button_box.append(&generate_btn);
    button_box.append(&cancel_btn);
    content_box.append(&button_box);

    dialog.set_child(Some(&content_box));

    let dialog_clone = dialog.clone();
    cancel_btn.connect_clicked(move |_| {
        dialog_clone.close();
    });

    let dialog_clone = dialog.clone();
    let parent_clone = parent.clone();
    generate_btn.connect_clicked(move |_| {
    // Sanitize inputs
    let name = match sanitize_uid_component(&name_entry.text()) {
        Ok(s) => s,
        Err(e) => { show_error_dialog(&parent_clone, &format!("Name error: {}", e)); return; }
    };
    let email = match sanitize_uid_component(&email_entry.text()) {
        Ok(s) => s,
        Err(e) => { show_error_dialog(&parent_clone, &format!("Email error: {}", e)); return; }
    };
    let comment = comment_entry.text().trim().to_string();
    if comment.contains(['<', '>', '(', ')', '"', '\'']) {
        show_error_dialog(&parent_clone, "Comment contains invalid characters");
        return;
    }

    match generate_pgp_key(&name, &email, &comment) {
        Ok(_) => {
            show_info_dialog(&parent_clone, "\n PGP key generated successfully! \n");
            dialog_clone.close();
        }
        Err(e) => show_error_dialog(&parent_clone, &format!("Failed to generate key: {}", e)),
    }
});


    dialog.present();
}

fn show_import_key_dialog(parent: &ApplicationWindow) {
    let dialog = Dialog::builder()
        .title("Import PGP Key")
        .transient_for(parent)
        .modal(true)
        .default_width(500)
        .default_height(400)
        .build();

    let content_box = Box::new(gtk4::Orientation::Vertical, 10);
    content_box.set_margin_top(10);
    content_box.set_margin_bottom(10);
    content_box.set_margin_start(10);
    content_box.set_margin_end(10);

    let label = Label::new(Some("Paste your PGP key here:"));
    label.set_halign(gtk4::Align::Start);

    let scrolled = ScrolledWindow::new();
    scrolled.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
    scrolled.set_vexpand(true);

    let text_view = TextView::new();
    text_view.set_wrap_mode(gtk4::WrapMode::Word);
    scrolled.set_child(Some(&text_view));

    let button_box = Box::new(gtk4::Orientation::Horizontal, 10);
    let import_btn = Button::with_label("Import");
    let cancel_btn = Button::with_label("Cancel");

    button_box.append(&import_btn);
    button_box.append(&cancel_btn);

    content_box.append(&label);
    content_box.append(&scrolled);
    content_box.append(&button_box);

    dialog.set_child(Some(&content_box));

    let dialog_clone = dialog.clone();
    cancel_btn.connect_clicked(move |_| {
        dialog_clone.close();
    });

    let dialog_clone = dialog.clone();
    let parent_clone = parent.clone();
    import_btn.connect_clicked(move |_| {
        let buffer = text_view.buffer();
        let key_data = buffer.text(&buffer.start_iter(), &buffer.end_iter(), false).to_string();

        if key_data.trim().is_empty() {
            show_error_dialog(&parent_clone, "Please paste a PGP key");
            return;
        }

        // Basic check for valid PGP block
        if !key_data.contains("-----BEGIN PGP") || !key_data.contains("-----END PGP") {
            show_error_dialog(&parent_clone, "Invalid PGP key format");
            return;
        }

        match import_pgp_key(&key_data) {
            Ok(output) => {
                show_info_dialog(&parent_clone, &format!("Key imported successfully!\n{}", output));
                dialog_clone.close();
            }
            Err(e) => show_error_dialog(&parent_clone, &format!("Failed to import key: {}", e)),
        }
    });


    dialog.present();
}

fn sanitize_recipient(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Recipient cannot be empty".to_string());
    }
    // Only allow alphanumerics, @, ., and - for email or key ID
    if !trimmed.chars().all(|c| c.is_alphanumeric() || c == '@' || c == '.' || c == '-' ) {
        return Err("Recipient contains invalid characters".to_string());
    }
    Ok(trimmed.to_string())
}

fn sanitize_message(message: &str) -> Result<String, String> {
    let trimmed = message.trim();
    if trimmed.is_empty() {
        return Err("Message cannot be empty".to_string());
    }
    Ok(trimmed.to_string())
}






fn delete_pgp_key(key_id: &str) -> Result<(), String> {
    let st_path = which("st").map_err(|_| "st terminal not found in PATH".to_string())?;

    // GPG command to run inside bash
    let bash_command = format!("gpg --pinentry-mode loopback --delete-secret-and-public-key {} ; echo 'Finished. Press Enter to close...' ; read", key_id);

    // Run st with proper args
    let status = Command::new(st_path)
        .arg("-e")
        .arg("bash")
        .arg("-c")
        .arg(&bash_command)
        .status()
        .map_err(|e| format!("Failed to spawn st terminal: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("GPG command failed with status: {}", status))
    }
}






fn sanitize_uid_component(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Field cannot be empty".to_string());
    }
    // Reject dangerous characters for gpg UID
    if trimmed.contains(['<', '>', '(', ')', '"', '\'']) {
        return Err("Invalid characters in input".to_string());
    }
    Ok(trimmed.to_string())
}



fn show_keys_dialog(parent: &ApplicationWindow) {
    let dialog = Dialog::builder()
        .title("My PGP Keys")
        .transient_for(parent)
        .modal(true)
        .default_width(600)
        .default_height(500)
        .build();

    let content_box = Box::new(gtk4::Orientation::Vertical, 10);
    content_box.set_margin_top(10);
    content_box.set_margin_bottom(10);
    content_box.set_margin_start(10);
    content_box.set_margin_end(10);

    // Scrolled area
    let scrolled = ScrolledWindow::new();
    scrolled.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
    scrolled.set_vexpand(true);

    // ListBox for keys
    let list_box = gtk4::ListBox::new();
    scrolled.set_child(Some(&list_box));

    // Load and display parsed keys
    match get_pgp_keys() {
        Ok(keys) => {
            for key in keys {
                let row_box = Box::new(gtk4::Orientation::Horizontal, 10);

                let label = Label::new(Some(&format!("{} <{}> [{}]", key.name, key.email, key.key_id)));
                label.set_halign(gtk4::Align::Start);

                // View button
                let view_btn = Button::with_label("View Public Key");
                let parent_clone = parent.clone();
                let key_id = key.key_id.clone();
                view_btn.connect_clicked(move |_| {
                    show_public_key_dialog(&parent_clone, &key_id);
                });

                row_box.append(&label);
                row_box.append(&view_btn);

                // Delete button
                let delete_btn = Button::with_label("Delete");
                let parent_clone = parent.clone();
                let key_id_clone = key.key_id.clone();
                let dialog_clone = dialog.clone();
                delete_btn.connect_clicked(move |_| {
                    let confirm = MessageDialog::builder()
                        .transient_for(&parent_clone)
                        .modal(true)
                        .buttons(gtk4::ButtonsType::YesNo)
                        .text(&format!("\n Please enter y to the terminal prompts to delete the key. \n"))
                        .message_type(gtk4::MessageType::Warning)
                        .build();

                    let parent_for_confirm = parent_clone.clone();
                    let key_id_confirm = key_id_clone.clone();
                    let dialog_for_confirm = dialog_clone.clone();
                    confirm.connect_response(move |confirm_dialog, response| {
                        if response == gtk4::ResponseType::Yes {
                            match delete_pgp_key(&key_id_confirm) {
                                Ok(_) => {
                                    /*
                                    match delete_pgp_key(&key_id_confirm){
                                        Ok(()) => {}
                                        Err(e) => show_error_dialog(&parent_for_confirm, &format!("Failed to delete key: {}", e)),
                                    }
                                    */
                                    // Close the current dialog
                                    dialog_for_confirm.close();
                                    // Reopen a fresh keys dialog
                                    show_keys_dialog(&parent_for_confirm);
                                    show_info_dialog(&parent_for_confirm, "\n Finished.\n");
                                }
                                Err(e) => show_error_dialog(&parent_for_confirm, &format!("Failed to delete key: {}", e)),
                            }
                        }
                        confirm_dialog.close();
                    });

                    confirm.present();
                });

                row_box.append(&delete_btn);

                let row = gtk4::ListBoxRow::new();
                row.set_child(Some(&row_box));
                list_box.append(&row);
            }
        }
        Err(e) => {
            let error_label = Label::new(Some(&format!("Error loading keys: {}", e)));
            list_box.append(&error_label);
        }
    }

    // Close button
    let button_box = Box::new(gtk4::Orientation::Horizontal, 10);
    let close_btn = Button::with_label("Close");
    button_box.append(&close_btn);

    content_box.append(&scrolled);
    content_box.append(&button_box);

    dialog.set_child(Some(&content_box));

    let dialog_clone = dialog.clone();
    close_btn.connect_clicked(move |_| {
        dialog_clone.close();
    });

    dialog.present();
}


fn show_private_key_content_dialog(parent: &ApplicationWindow, priv_key: &str) {
    let dialog = gtk4::Dialog::builder()
        .title("Private Key Content")
        .transient_for(parent)
        .modal(true)
        .default_width(700)
        .default_height(600)
        .build();

    let content_box = gtk4::Box::new(gtk4::Orientation::Vertical, 10);
    content_box.set_margin_top(10);
    content_box.set_margin_bottom(10);
    content_box.set_margin_start(10);
    content_box.set_margin_end(10);

    

    // Scrolled TextView
    let scrolled = gtk4::ScrolledWindow::new();
    scrolled.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
    scrolled.set_vexpand(true); // only this expands
    let text_view = gtk4::TextView::new();
    text_view.set_editable(false);
    text_view.set_wrap_mode(gtk4::WrapMode::Word);
    text_view.set_monospace(true);
    text_view.buffer().set_text(priv_key);
    scrolled.set_child(Some(&text_view));

    content_box.append(&scrolled);

    // Close button at bottom
    let button_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 10);
    let close_btn = gtk4::Button::with_label("Close");
    button_box.append(&close_btn);
    content_box.append(&button_box);

    dialog.set_child(Some(&content_box));

    let dialog_clone = dialog.clone();
    close_btn.connect_clicked(move |_| {
        dialog_clone.close();
    });

    dialog.present();
}






fn show_encrypt_dialog(parent: &ApplicationWindow) {
    let dialog = Dialog::builder()
        .title("Encrypt Message")
        .transient_for(parent)
        .modal(true)
        .default_width(600)
        .default_height(600)
        .build();

    let content_box = Box::new(gtk4::Orientation::Vertical, 10);
    content_box.set_margin_top(10);
    content_box.set_margin_bottom(10);
    content_box.set_margin_start(10);
    content_box.set_margin_end(10);

    // Recipient label and entry
    let recipient_label = Label::new(Some("Recipient email or key ID:"));
    recipient_label.set_halign(gtk4::Align::Start);
    let recipient_entry = Entry::new();

    // List of keys section
    let list_label = Label::new(Some("Select a recipient from your keys:"));
    list_label.set_halign(gtk4::Align::Start);

    // Search entry for filtering keys
    let search_entry = SearchEntry::new();
    search_entry.set_placeholder_text(Some("Search keys by name, email, or key ID..."));

    let scrolled_keys = ScrolledWindow::new();
    scrolled_keys.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
    scrolled_keys.set_vexpand(true);

    let list_box = gtk4::ListBox::new();
    scrolled_keys.set_child(Some(&list_box));

    // Store all keys for filtering
    let all_keys = Rc::new(RefCell::new(Vec::new()));

    // Load keys into the list and store them
    if let Ok(keys) = get_pgp_keys() {
        *all_keys.borrow_mut() = keys.clone();
        populate_key_list(&list_box, &keys, &recipient_entry);
    }

    // Set up search functionality
    let all_keys_clone = all_keys.clone();
    let list_box_clone = list_box.clone();
    let recipient_entry_clone = recipient_entry.clone();
    
    search_entry.connect_search_changed(move |search_entry| {
        let search_text = search_entry.text().to_lowercase();
        let all_keys = all_keys_clone.borrow();
        
        // Clear current list
        while let Some(child) = list_box_clone.first_child() {
            list_box_clone.remove(&child);
        }
        
        // Filter keys based on search text
        let filtered_keys: Vec<_> = if search_text.is_empty() {
            all_keys.clone()
        } else {
            all_keys.iter()
                .filter(|key| {
                    key.name.to_lowercase().contains(&search_text) ||
                    key.email.to_lowercase().contains(&search_text) ||
                    key.key_id.to_lowercase().contains(&search_text)
                })
                .cloned()
                .collect()
        };
        
        // Repopulate with filtered keys
        populate_key_list(&list_box_clone, &filtered_keys, &recipient_entry_clone);
    });

    // Message input
    let message_label = Label::new(Some("Message to encrypt:"));
    message_label.set_halign(gtk4::Align::Start);

    let scrolled_input = ScrolledWindow::new();
    scrolled_input.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
    scrolled_input.set_vexpand(true);

    let input_text_view = TextView::new();
    input_text_view.set_wrap_mode(gtk4::WrapMode::Word);
    scrolled_input.set_child(Some(&input_text_view));

    // Encrypted message output
    let result_label = Label::new(Some("Encrypted message:"));
    result_label.set_halign(gtk4::Align::Start);

    let scrolled_output = ScrolledWindow::new();
    scrolled_output.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
    scrolled_output.set_vexpand(true);

    let output_text_view = TextView::new();
    output_text_view.set_editable(false);
    output_text_view.set_wrap_mode(gtk4::WrapMode::Word);
    scrolled_output.set_child(Some(&output_text_view));

    // Buttons
    let button_box = Box::new(gtk4::Orientation::Horizontal, 10);
    let encrypt_btn = Button::with_label("Encrypt");
    let close_btn = Button::with_label("Close");
    button_box.append(&encrypt_btn);
    button_box.append(&close_btn);

    // Add widgets to content
    content_box.append(&recipient_label);
    content_box.append(&recipient_entry);
    content_box.append(&list_label);
    content_box.append(&search_entry);  // Add search entry here
    content_box.append(&scrolled_keys);
    content_box.append(&message_label);
    content_box.append(&scrolled_input);
    content_box.append(&result_label);
    content_box.append(&scrolled_output);
    content_box.append(&button_box);

    dialog.set_child(Some(&content_box));

    // Close action
    let dialog_clone = dialog.clone();
    close_btn.connect_clicked(move |_| {
        dialog_clone.close();
    });

    // Encrypt action
    let parent_clone = parent.clone();
    encrypt_btn.connect_clicked(move |_| {
        // Sanitize recipient
        let recipient = match sanitize_recipient(&recipient_entry.text()) {
            Ok(r) => r,
            Err(e) => { show_error_dialog(&parent_clone, &format!("Recipient error: {}", e)); return; }
        };

        // Sanitize message
        let buffer = input_text_view.buffer();
        let message = match sanitize_message(&buffer.text(&buffer.start_iter(), &buffer.end_iter(), false)) {
            Ok(m) => m,
            Err(e) => { show_error_dialog(&parent_clone, &format!("Message error: {}", e)); return; }
        };

        match encrypt_message(&recipient, &message) {
            Ok(encrypted) => output_text_view.buffer().set_text(&encrypted),
            Err(e) => show_error_dialog(&parent_clone, &format!("Encryption failed: {}", e)),
        }
    });


    dialog.present();
}

fn populate_key_list(list_box: &gtk4::ListBox, keys: &[PgpKey], recipient_entry: &Entry) {
    for key in keys {
        let row_box = Box::new(gtk4::Orientation::Horizontal, 10);
        let label = Label::new(Some(&format!("{} <{}> [{}]", key.name, key.email, key.key_id)));
        label.set_halign(gtk4::Align::Start);

        let select_btn = Button::with_label("Select");
        let recipient_entry_clone = recipient_entry.clone();
        let key_id = key.key_id.clone();
        select_btn.connect_clicked(move |_| {
            recipient_entry_clone.set_text(&key_id);
        });

        row_box.append(&label);
        row_box.append(&select_btn);

        let row = gtk4::ListBoxRow::new();
        row.set_child(Some(&row_box));
        list_box.append(&row);
    }
}


fn show_decrypt_dialog(parent: &ApplicationWindow) {
    let dialog = Dialog::builder()
        .title("Decrypt Message")
        .transient_for(parent)
        .modal(true)
        .default_width(600)
        .default_height(500)
        .build();

    let content_box = Box::new(gtk4::Orientation::Vertical, 10);
    content_box.set_margin_top(10);
    content_box.set_margin_bottom(10);
    content_box.set_margin_start(10);
    content_box.set_margin_end(10);

    let message_label = Label::new(Some("Encrypted message:"));
    message_label.set_halign(gtk4::Align::Start);

    let scrolled_input = ScrolledWindow::new();
    scrolled_input.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
    scrolled_input.set_vexpand(true);

    let input_text_view = TextView::new();
    input_text_view.set_wrap_mode(gtk4::WrapMode::Word);
    scrolled_input.set_child(Some(&input_text_view));

    let result_label = Label::new(Some("Decrypted message:"));
    result_label.set_halign(gtk4::Align::Start);

    let scrolled_output = ScrolledWindow::new();
    scrolled_output.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
    scrolled_output.set_vexpand(true);

    let output_text_view = TextView::new();
    output_text_view.set_editable(false);
    output_text_view.set_wrap_mode(gtk4::WrapMode::Word);
    scrolled_output.set_child(Some(&output_text_view));

    let button_box = Box::new(gtk4::Orientation::Horizontal, 10);
    let decrypt_btn = Button::with_label("Decrypt");
    let close_btn = Button::with_label("Close");

    button_box.append(&decrypt_btn);
    button_box.append(&close_btn);

    content_box.append(&message_label);
    content_box.append(&scrolled_input);
    content_box.append(&result_label);
    content_box.append(&scrolled_output);
    content_box.append(&button_box);

    dialog.set_child(Some(&content_box));

    let dialog_clone = dialog.clone();
    close_btn.connect_clicked(move |_| {
        dialog_clone.close();
    });

    let parent_clone = parent.clone();
    decrypt_btn.connect_clicked(move |_| {
        let buffer = input_text_view.buffer();
        let encrypted_message = match sanitize_message(&buffer.text(&buffer.start_iter(), &buffer.end_iter(), false)) {
            Ok(m) => m,
            Err(e) => { show_error_dialog(&parent_clone, &format!("Message error: {}", e)); return; }
        };

        match decrypt_message(&encrypted_message) {
            Ok(decrypted) => output_text_view.buffer().set_text(&decrypted),
            Err(e) => show_error_dialog(&parent_clone, &format!("Decryption failed: {}", e)),
        }
    });


    dialog.present();
}

// Helper functions for dialogs
fn show_error_dialog(parent: &ApplicationWindow, message: &str) {
    let dialog = MessageDialog::builder()
        .transient_for(parent)
        .modal(true)
        .buttons(gtk4::ButtonsType::Ok)
        .text(message)
        .message_type(gtk4::MessageType::Error)
        .build();

    dialog.connect_response(|dialog, _| {
        dialog.close();
    });

    dialog.present();
}

fn show_info_dialog(parent: &ApplicationWindow, message: &str) {
    let dialog = MessageDialog::builder()
        .transient_for(parent)
        .modal(true)
        .buttons(gtk4::ButtonsType::Ok)
        .text(message)
        .message_type(gtk4::MessageType::Info)
        .build();
        

    dialog.connect_response(|dialog, _| {
        dialog.close();
    });

    dialog.present();
}

// PGP operations using gpg 
fn generate_pgp_key(name: &str, email: &str, comment: &str) -> Result<String, String> {
    // Build the uid string: Name (Comment) <Email>
    let uid = if comment.is_empty() {
        format!("{} <{}>", name, email)
    } else {
        format!("{} ({}) <{}>", name, comment, email)
    };

    let output = Command::new("gpg")
        .args([
            "--batch",
            "--yes",
            "--pinentry-mode", "loopback",
            "--passphrase", "",
            "--quick-generate-key",
            &uid,
            "rsa4096",
            "sign,encrypt,auth",
            "0", // 0 = never expire
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to start gpg: {}", e))?;

    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    if !output.stderr.is_empty() {
        if !combined.is_empty() { combined.push('\n'); }
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
    }

    if output.status.success() {
        Ok(combined)
    } else {
        Err(combined)
    }
}



fn import_pgp_key(key_data: &str) -> Result<String, String> {
    let output = Command::new("gpg")
        .args(["--import"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start gpg: {}", e))?;

    let mut child = output;
    if let Some(stdin) = child.stdin.as_mut() {
        use std::io::Write;
        stdin.write_all(key_data.as_bytes())
            .map_err(|e| format!("Failed to write to gpg stdin: {}", e))?;
    }

    let result = child.wait_with_output()
        .map_err(|e| format!("Failed to execute gpg: {}", e))?;

    if result.status.success() {
        let stderr_output = String::from_utf8_lossy(&result.stderr);
        Ok(stderr_output.to_string())
    } else {
        Err(String::from_utf8_lossy(&result.stderr).to_string())
    }
}



#[derive(Debug, Clone)]
struct PgpKey {
    key_id: String,
    name: String,
    email: String,
}



fn get_pgp_keys() -> Result<Vec<PgpKey>, String> {
    let output = Command::new("gpg")
        .args(["--list-keys", "--with-colons"])
        .output()
        .map_err(|e| format!("Failed to execute gpg: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut keys = Vec::new();
    let mut current_key_id = String::new();
    let mut current_name = String::new();
    let mut current_email = String::new();

    for line in output_str.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        
        match fields.get(0) {
            Some(&"pub") => {
                // Public key line - get key ID (last 8 characters of fingerprint)
                if let Some(key_id) = fields.get(4) {
                    current_key_id = if key_id.len() > 8 {
                        key_id[key_id.len()-8..].to_string()
                    } else {
                        key_id.to_string()
                    };
                }
            }
            Some(&"uid") => {
                // User ID line - get name and email
                if let Some(uid) = fields.get(9) {
                    // Parse "Name (Comment) <email@example.com>" format
                    if let Some(email_start) = uid.rfind('<') {
                        if let Some(email_end) = uid.rfind('>') {
                            current_email = uid[email_start + 1..email_end].to_string();
                            let name_part = uid[..email_start].trim();
                            
                            // Remove comment in parentheses if present
                            if let Some(comment_start) = name_part.rfind('(') {
                                current_name = name_part[..comment_start].trim().to_string();
                            } else {
                                current_name = name_part.to_string();
                            }
                        }
                    } else {
                        // Fallback if format is different
                        current_name = uid.to_string();
                        current_email = "No email".to_string();
                    }
                    
                    // Add the key when we have all the info
                    if !current_key_id.is_empty() && !current_name.is_empty() {
                        keys.push(PgpKey {
                            key_id: current_key_id.clone(),
                            name: current_name.clone(),
                            email: current_email.clone(),
                        });
                        
                        // Reset for next key
                        current_key_id.clear();
                        current_name.clear();
                        current_email.clear();
                    }
                }
            }
            _ => {}
        }
    }

    Ok(keys)
}


fn show_private_keys_dialog(parent: &ApplicationWindow) {
    //Set up info for the private keys dialog
    let dialog = Dialog::builder()
        .title("My Private PGP Keys")
        .transient_for(parent)
        .modal(true)
        .default_width(600)
        .default_height(500)
        .build();

    let content_box = Box::new(gtk4::Orientation::Vertical, 10);
    content_box.set_margin_top(10);
    content_box.set_margin_bottom(10);
    content_box.set_margin_start(10);
    content_box.set_margin_end(10);

    // Scrolled area
    let scrolled = ScrolledWindow::new();
    scrolled.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
    scrolled.set_vexpand(true);

    // ListBox for keys
    let list_box = gtk4::ListBox::new();
    scrolled.set_child(Some(&list_box));
    content_box.append(&scrolled);

    // Load and display parsed private keys
    match get_pgp_private_keys() {
        Ok(keys) => {
            for key in keys {
                let row_box = Box::new(gtk4::Orientation::Horizontal, 10);

                let label = Label::new(Some(&format!(
                    "{} <{}> [{}]",
                    key.name, key.email, key.key_id
                )));
                label.set_halign(gtk4::Align::Start);

                let view_btn = Button::with_label("View Private Key");
                let parent_clone = parent.clone();
                let key_id = key.key_id.clone();
                view_btn.connect_clicked(move |_| {
                    match export_private_key(&key_id) {
                        Ok(priv_key) => show_private_key_content_dialog(&parent_clone, &priv_key),
                        Err(e) => show_error_dialog(&parent_clone, &format!("Error exporting private key: {}", e)),
                    }
                });

                row_box.append(&label);
                row_box.append(&view_btn);

                let row = gtk4::ListBoxRow::new();
                row.set_child(Some(&row_box));
                list_box.append(&row);
            }
        }
        Err(e) => {
            let error_label = Label::new(Some(&format!("Error loading private keys: {}", e)));
            list_box.append(&error_label);
        }
    }

    // Close button
    let button_box = Box::new(gtk4::Orientation::Horizontal, 10);
    let close_btn = Button::with_label("Close");
    button_box.append(&close_btn);
    content_box.append(&button_box);

    dialog.set_child(Some(&content_box));

    let dialog_clone = dialog.clone();
    close_btn.connect_clicked(move |_| {
        dialog_clone.close();
    });

    dialog.present();
}

fn get_pgp_private_keys() -> Result<Vec<PgpKey>, String> {
    let output = Command::new("gpg")
        .args(["--list-secret-keys", "--with-colons"])
        .output()
        .map_err(|e| format!("Failed to execute gpg: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut keys = Vec::new();
    let mut current_key_id = String::new();
    let mut current_name = String::new();
    let mut current_email = String::new();

    for line in output_str.lines() {
        let fields: Vec<&str> = line.split(':').collect();

        match fields.get(0) {
            Some(&"sec") => {
                if let Some(key_id) = fields.get(4) {
                    current_key_id = if key_id.len() > 8 {
                        key_id[key_id.len()-8..].to_string()
                    } else {
                        key_id.to_string()
                    };
                }
            }
            Some(&"uid") => {
                if let Some(uid) = fields.get(9) {
                    if let Some(email_start) = uid.rfind('<') {
                        if let Some(email_end) = uid.rfind('>') {
                            current_email = uid[email_start + 1..email_end].to_string();
                            let name_part = uid[..email_start].trim();
                            if let Some(comment_start) = name_part.rfind('(') {
                                current_name = name_part[..comment_start].trim().to_string();
                            } else {
                                current_name = name_part.to_string();
                            }
                        }
                    } else {
                        current_name = uid.to_string();
                        current_email = "No email".to_string();
                    }

                    if !current_key_id.is_empty() && !current_name.is_empty() {
                        keys.push(PgpKey {
                            key_id: current_key_id.clone(),
                            name: current_name.clone(),
                            email: current_email.clone(),
                        });
                        current_key_id.clear();
                        current_name.clear();
                        current_email.clear();
                    }
                }
            }
            _ => {}
        }
    }

    Ok(keys)
}



fn show_public_key_dialog(parent: &ApplicationWindow, key_id: &str) {
    //Set up info for the private keys dialog
    let dialog = Dialog::builder()
        .title(&format!("Public Key: {}", key_id))
        .transient_for(parent)
        .modal(true)
        .default_width(700)
        .default_height(600)
        .build();

    let content_box = Box::new(gtk4::Orientation::Vertical, 10);
    content_box.set_margin_top(10);
    content_box.set_margin_bottom(10);
    content_box.set_margin_start(10);
    content_box.set_margin_end(10);

    let scrolled = ScrolledWindow::new();
    scrolled.set_policy(gtk4::PolicyType::Automatic, gtk4::PolicyType::Automatic);
    scrolled.set_vexpand(true);

    let text_view = TextView::new();
    text_view.set_editable(false);
    text_view.set_wrap_mode(gtk4::WrapMode::Word);
    text_view.set_monospace(true);
    scrolled.set_child(Some(&text_view));

    // Export the public key
    match export_public_key(key_id) {
        Ok(public_key) => {
            text_view.buffer().set_text(&public_key);
        }
        Err(e) => {
            text_view.buffer().set_text(&format!("Error exporting public key: {}", e));
        }
    }

    let button_box = Box::new(gtk4::Orientation::Horizontal, 10);
    let close_btn = Button::with_label("Close");

    button_box.append(&close_btn);

    content_box.append(&scrolled);
    content_box.append(&button_box);

    dialog.set_child(Some(&content_box));

    let dialog_clone = dialog.clone();
    close_btn.connect_clicked(move |_| {
        dialog_clone.close();
    });

    dialog.present();
}

fn export_public_key(key_id: &str) -> Result<String, String> {
    let output = Command::new("gpg")
        .args(["--armor", "--export", key_id])
        .output()
        .map_err(|e| format!("Failed to execute gpg: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn export_private_key(key_id: &str) -> Result<String, String> {
    let output = Command::new("gpg")
        .args(["--armor", "--export-secret-keys", key_id])
        .output()
        .map_err(|e| format!("Failed to execute gpg: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn encrypt_message(recipient: &str, message: &str) -> Result<String, String> {
    let output = Command::new("gpg")
        .args(["--armor", "--encrypt", "--recipient", recipient])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start gpg: {}", e))?;

    let mut child = output;
    if let Some(stdin) = child.stdin.as_mut() {
        use std::io::Write;
        stdin.write_all(message.as_bytes())
            .map_err(|e| format!("Failed to write to gpg stdin: {}", e))?;
    }

    let result = child.wait_with_output()
        .map_err(|e| format!("Failed to execute gpg: {}", e))?;

    if result.status.success() {
        Ok(String::from_utf8_lossy(&result.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&result.stderr).to_string())
    }
}

fn decrypt_message(encrypted_message: &str) -> Result<String, String> {
    let output = Command::new("gpg")
        .args(["--decrypt"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start gpg: {}", e))?;

    let mut child = output;
    if let Some(stdin) = child.stdin.as_mut() {
        use std::io::Write;
        stdin.write_all(encrypted_message.as_bytes())
            .map_err(|e| format!("Failed to write to gpg stdin: {}", e))?;
    }

    let result = child.wait_with_output()
        .map_err(|e| format!("Failed to execute gpg: {}", e))?;

    if result.status.success() {
        Ok(String::from_utf8_lossy(&result.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&result.stderr).to_string())
    }
}
