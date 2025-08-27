    # Event Handlers
    
    def _on_alert(self, alert):
        """Handle a new alert."""
        # This will be called from a different thread, so we need to use after()
        self.after(0, self._add_alert_to_ui, alert)
    
    def _add_alert_to_ui(self, alert):
        """Add an alert to the UI."""
        # Add to dashboard alerts
        timestamp = datetime.fromtimestamp(alert['timestamp']).strftime('%H:%M:%S')
        severity = alert.get('severity', 'info').title()
        description = alert.get('description', '')[:100] + ('...' if len(alert.get('description', '')) > 100 else '')
        
        # Insert at the top
        self.alerts_tree.insert('', 0, 
            values=(timestamp, severity, description),
            tags=(severity.lower(),)
        )
        
        # Keep only the last 10 alerts
        if len(self.alerts_tree.get_children()) > 10:
            self.alerts_tree.delete(self.alerts_tree.get_children()[-1])
        
        # Update alerts tab if visible
        if self.notebook.tab(self.notebook.select(), 'text') == 'Alerts':
            self._populate_alerts()
    
    def _on_alert_double_click(self, event):
        """Handle double-click on an alert."""
        # Get selected item
        selection = self.alerts_table.selection()
        if not selection:
            return
        
        # Get alert details
        item = self.alerts_table.item(selection[0])
        alert_time = item['values'][0]
        alert_severity = item['values'][1]
        alert_rule = item['values'][2]
        alert_desc = item['values'][3]
        
        # Create details window
        details_win = tk.Toplevel(self)
        details_win.title(f"Alert Details - {alert_rule}")
        details_win.geometry("600x400")
        
        # Create text widget for details
        text = scrolledtext.ScrolledText(details_win, wrap=tk.WORD)
        text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Add alert details
        text.insert('end', f"Time: {alert_time}\n")
        text.insert('end', f"Severity: {alert_severity}\n")
        text.insert('end', f"Rule: {alert_rule}\n")
        text.insert('end', "\nDescription:\n")
        text.insert('end', f"{alert_desc}\n\n")
        
        # Add more details if available
        # This would come from the actual alert details
        text.insert('end', "Additional Details:\n")
        text.insert('end', "No additional details available.\n")
        
        # Make text read-only
        text.config(state='disabled')
        
        # Add close button
        ttk.Button(
            details_win, 
            text="Close", 
            command=details_win.destroy
        ).pack(pady=10)
    
    def _on_rule_double_click(self, event):
        """Handle double-click on a rule."""
        self._edit_rule()
    
    def _on_whitelist_type_changed(self, event=None):
        """Handle whitelist type change."""
        self._populate_whitelist()
    
    # Button Handlers
    
    def _toggle_hips(self):
        """Toggle HIPS on/off."""
        if self.hips_manager.running:
            self.hips_manager.stop()
        else:
            self.hips_manager.start()
        
        # Update UI
        self._update_status()
    
    def _show_settings(self):
        """Show settings dialog."""
        settings_win = tk.Toplevel(self)
        settings_win.title("HIPS Settings")
        settings_win.geometry("500x400")
        
        # Create notebook for settings tabs
        notebook = ttk.Notebook(settings_win)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # General settings tab
        general_tab = ttk.Frame(notebook)
        notebook.add(general_tab, text="General")
        
        # Add settings controls here
        ttk.Label(general_tab, text="Settings will be available in a future update.").pack(pady=20)
        
        # Close button
        ttk.Button(
            settings_win, 
            text="Close", 
            command=settings_win.destroy
        ).pack(pady=10)
    
    def _refresh_alerts(self):
        """Refresh the alerts table."""
        self._populate_alerts()
    
    def _clear_alerts(self):
        """Clear all alerts."""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all alerts?"):
            self.hips_manager.clear_alerts()
            self._populate_alerts()
    
    def _export_alerts(self):
        """Export alerts to a file."""
        # Get save file path
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export Alerts"
        )
        
        if not file_path:
            return
        
        try:
            # Get alerts
            alerts = self.hips_manager.get_alerts(limit=0)  # Get all alerts
            
            # Format alerts for export
            export_data = []
            for alert in alerts:
                export_alert = {
                    'timestamp': datetime.fromtimestamp(alert['timestamp']).isoformat(),
                    'rule_id': alert['rule_id'],
                    'rule_name': alert['rule_name'],
                    'severity': alert['severity'],
                    'description': alert['description'],
                    'details': alert['details']
                }
                export_data.append(export_alert)
            
            # Write to file
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            messagebox.showinfo("Success", f"Exported {len(export_data)} alerts to {file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export alerts: {e}")
    
    def _add_rule(self):
        """Add a new rule."""
        self._show_rule_editor()
    
    def _edit_rule(self):
        """Edit the selected rule."""
        selection = self.rules_table.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a rule to edit.")
            return
        
        # Get rule ID
        item = self.rules_table.item(selection[0])
        rule_id = item['values'][1]  # ID is in the second column
        
        # Get rule details
        rule = self.hips_manager.get_rule(rule_id)
        if not rule:
            messagebox.showerror("Error", f"Rule with ID {rule_id} not found.")
            return
        
        # Show editor
        self._show_rule_editor(rule)
    
    def _delete_rule(self):
        """Delete the selected rule."""
        selection = self.rules_table.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a rule to delete.")
            return
        
        # Get rule ID
        item = self.rules_table.item(selection[0])
        rule_id = item['values'][1]  # ID is in the second column
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete rule '{item['values'][2]}'?"):
            return
        
        # Delete rule
        if self.hips_manager.delete_rule(rule_id):
            self._populate_rules()
            messagebox.showinfo("Success", "Rule deleted successfully.")
        else:
            messagebox.showerror("Error", "Failed to delete rule.")
    
    def _import_rules(self):
        """Import rules from a file."""
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Import Rules"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'r') as f:
                rules = json.load(f)
            
            if not isinstance(rules, list):
                messagebox.showerror("Error", "Invalid rules file format. Expected a list of rules.")
                return
            
            # Import each rule
            imported = 0
            for rule in rules:
                if self.hips_manager.add_rule(rule):
                    imported += 1
            
            # Refresh rules display
            self._populate_rules()
            
            messagebox.showinfo("Success", f"Imported {imported} of {len(rules)} rules.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import rules: {e}")
    
    def _export_rules(self):
        """Export rules to a file."""
        # Get save file path
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export Rules"
        )
        
        if not file_path:
            return
        
        try:
            # Get rules
            rules = self.hips_manager.get_rules()
            
            # Write to file
            with open(file_path, 'w') as f:
                json.dump(rules, f, indent=2)
            
            messagebox.showinfo("Success", f"Exported {len(rules)} rules to {file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export rules: {e}")
    
    def _add_whitelist_item(self):
        """Add an item to the whitelist."""
        whitelist_type = self.whitelist_type.get()
        if not whitelist_type:
            return
        
        # Show input dialog
        item = simpledialog.askstring("Add to Whitelist", f"Enter {whitelist_type.replace('_', ' ')} to whitelist:")
        if not item:
            return
        
        # Add to whitelist
        if self.hips_manager.add_to_whitelist(whitelist_type, item):
            self._populate_whitelist()
            messagebox.showinfo("Success", "Item added to whitelist.")
        else:
            messagebox.showwarning("Warning", "Item already exists in whitelist.")
    
    def _remove_whitelist_item(self):
        """Remove selected items from the whitelist."""
        whitelist_type = self.whitelist_type.get()
        if not whitelist_type:
            return
        
        # Get selected items
        selection = self.whitelist_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select items to remove.")
            return
        
        # Confirm removal
        if not messagebox.askyesno("Confirm Removal", f"Remove {len(selection)} items from whitelist?"):
            return
        
        # Remove selected items
        removed = 0
        for idx in reversed(selection):  # Reverse to maintain correct indices
            item = self.whitelist_listbox.get(idx)
            if self.hips_manager.remove_from_whitelist(whitelist_type, item):
                removed += 1
        
        # Refresh display
        self._populate_whitelist()
        
        messagebox.showinfo("Success", f"Removed {removed} items from whitelist.")
    
    def _import_whitelist(self):
        """Import whitelist from a file."""
        whitelist_type = self.whitelist_type.get()
        if not whitelist_type:
            return
        
        file_path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")],
            title=f"Import {whitelist_type.replace('_', ' ').title()} Whitelist"
        )
        
        if not file_path:
            return
        
        try:
            items = []
            
            # Check file extension to determine format
            if file_path.lower().endswith('.json'):
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        items = data.get(whitelist_type, [])
                    elif isinstance(data, list):
                        items = data
                    else:
                        raise ValueError("Invalid JSON format. Expected an object or array.")
            else:
                # Assume plain text file with one item per line
                with open(file_path, 'r') as f:
                    items = [line.strip() for line in f if line.strip()]
            
            # Add items to whitelist
            added = 0
            for item in items:
                if self.hips_manager.add_to_whitelist(whitelist_type, item):
                    added += 1
            
            # Refresh display
            self._populate_whitelist()
            
            messagebox.showinfo("Success", f"Imported {added} items to whitelist.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import whitelist: {e}")
    
    def _export_whitelist(self):
        """Export whitelist to a file."""
        whitelist_type = self.whitelist_type.get()
        if not whitelist_type:
            return
        
        # Get save file path
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"), 
                ("JSON files", "*.json"), 
                ("All files", "*.*")
            ],
            title=f"Export {whitelist_type.replace('_', ' ').title()} Whitelist"
        )
        
        if not file_path:
            return
        
        try:
            # Get whitelist items
            items = self.hips_manager.get_whitelist(whitelist_type)
            
            # Write to file
            if file_path.lower().endswith('.json'):
                with open(file_path, 'w') as f:
                    json.dump({whitelist_type: items}, f, indent=2)
            else:
                with open(file_path, 'w') as f:
                    for item in sorted(items):
                        f.write(f"{item}\n")
            
            messagebox.showinfo("Success", f"Exported {len(items)} items to {file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export whitelist: {e}")
    
    def _toggle_monitoring(self, monitor_type):
        """Toggle monitoring of a specific type."""
        enabled = self.monitoring_vars[monitor_type].get()
        self.hips_manager.set_monitoring(monitor_type, enabled)
    
    def _filter_alerts(self):
        """Filter alerts by severity."""
        # This would be implemented to filter the alerts table
        # based on the selected severity
        pass
    
    def _sort_alerts(self, column):
        """Sort alerts by the specified column."""
        # This would be implemented to sort the alerts table
        # by the clicked column
        pass
    
    def _show_rule_editor(self, rule=None):
        """Show the rule editor dialog."""
        # This would be implemented to show a dialog for adding/editing rules
        messagebox.showinfo("Info", "Rule editor will be implemented in a future update.")
    
    def _schedule_update(self):
        """Schedule the next status update."""
        self._update_status()
        # Update every 5 seconds
        self.after(5000, self._schedule_update)
    
    def destroy(self):
        """Clean up resources."""
        # Stop any running operations
        if hasattr(self, 'hips_manager') and self.hips_manager.running:
            self.hips_manager.stop()
        
        # Call parent destroy
        super().destroy()
