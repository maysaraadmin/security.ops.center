import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from typing import Dict, List, Optional, Tuple
from models.rule import RuleModel

class RulesView:
    def __init__(self, parent, rule_model: RuleModel):
        self.rule_model = rule_model
        self.frame = ttk.Frame(parent)
        
        # Store the original rule data for edit comparisons
        self.original_rules: Dict[int, Dict] = {}
        
        self._create_widgets()
        self.update_rules_table()

    def _create_widgets(self):
        """Create all widgets for the rules view"""
        # Main container frame
        main_frame = ttk.Frame(self.frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Search and filter frame
        filter_frame = ttk.Frame(main_frame)
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Search box
        ttk.Label(filter_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.search_entry = ttk.Entry(filter_frame, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        self.search_entry.bind('<Return>', lambda e: self.update_rules_table())
        
        # Search button
        search_btn = ttk.Button(filter_frame, text="Search", command=self.update_rules_table)
        search_btn.pack(side=tk.LEFT, padx=5)
        
        # Clear button
        clear_btn = ttk.Button(filter_frame, text="Clear", command=self.clear_search)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Rules treeview
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.rules_tree = ttk.Treeview(
            tree_frame,
            columns=('id', 'name', 'condition', 'action', 'severity', 'enabled'),
            show='headings',
            selectmode='extended'
        )
        
        # Define columns
        columns = [
            ('id', 'ID', 50),
            ('name', 'Rule Name', 200),
            ('condition', 'Condition', 400),
            ('action', 'Action', 100),
            ('severity', 'Severity', 80),
            ('enabled', 'Enabled', 80)
        ]
        
        for col_id, heading, width in columns:
            self.rules_tree.heading(col_id, text=heading)
            self.rules_tree.column(col_id, width=width, anchor=tk.CENTER)
        
        # Hide ID column by default
        self.rules_tree.column('id', width=0, stretch=tk.NO)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.rules_tree.yview)
        self.rules_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack tree and scrollbar
        self.rules_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure tags for enabled/disabled rules
        self.rules_tree.tag_configure('enabled', background='#f0fff0')  # Light green
        self.rules_tree.tag_configure('disabled', background='#fff0f0')  # Light red
        
        # Action buttons frame
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=(5, 0))
        
        # Create action buttons
        actions = [
            ('Add Rule', self.add_rule),
            ('Edit Rule', self.edit_rule),
            ('Delete Rule', self.delete_rule),
            ('Toggle Enable', self.toggle_rule),
            ('Duplicate Rule', self.duplicate_rule),
            ('Test Rule', self.test_rule),
            ('Refresh', self.update_rules_table)
        ]
        
        for text, command in actions:
            btn = ttk.Button(action_frame, text=text, command=command)
            btn.pack(side=tk.LEFT, padx=2)
        
        # Context menu
        self.context_menu = tk.Menu(self.frame, tearoff=0)
        self.context_menu.add_command(label="Edit Rule", command=self.edit_rule)
        self.context_menu.add_command(label="Toggle Enable", command=self.toggle_rule)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Duplicate Rule", command=self.duplicate_rule)
        self.context_menu.add_command(label="Delete Rule", command=self.delete_rule)
        
        # Bind right-click event
        self.rules_tree.bind("<Button-3>", self.show_context_menu)
        
        # Bind double-click to edit
        self.rules_tree.bind("<Double-1>", lambda e: self.edit_rule())

    def update_rules_table(self):
        """Update the rules table with current data and filters"""
        # Clear existing data
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
        
        # Get search term
        search_term = self.search_entry.get().strip()
        
        # Get all rules (filtered if search term exists)
        rules = self.rule_model.get_all_rules()
        
        # Store original rule data for edit comparisons
        self.original_rules = {rule['id']: rule.copy() for rule in rules}
        
        # Filter rules if search term exists
        if search_term:
            search_lower = search_term.lower()
            rules = [
                rule for rule in rules
                if (search_lower in rule['name'].lower() or 
                    search_lower in rule['condition'].lower())
            ]
        
        # Add rules to treeview with appropriate tags
        for rule in rules:
            tags = ('enabled',) if rule['enabled'] else ('disabled',)
            self.rules_tree.insert(
                '', tk.END,
                values=(
                    rule['id'],
                    rule['name'],
                    rule['condition'],
                    rule['action'],
                    self._get_severity_label(rule['severity']),
                    'Yes' if rule['enabled'] else 'No'
                ),
                tags=tags
            )

    def clear_search(self):
        """Clear the search box and refresh the table"""
        self.search_entry.delete(0, tk.END)
        self.update_rules_table()

    def add_rule(self):
        """Open dialog to add a new rule"""
        dialog = RuleEditDialog(
            self.frame,
            title="Add New Rule",
            rule_model=self.rule_model
        )
        
        if dialog.result:
            # Refresh the table to show the new rule
            self.update_rules_table()
            messagebox.showinfo("Success", "Rule added successfully")

    def edit_rule(self):
        """Edit the selected rule"""
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule to edit")
            return
        
        # Get the first selected item (in case of multi-select)
        item = self.rules_tree.item(selected[0])
        rule_id = item['values'][0]
        
        # Get the full rule data
        rule = self.rule_model.get_rule_by_id(rule_id)
        if not rule:
            messagebox.showerror("Error", "Rule not found")
            return
        
        dialog = RuleEditDialog(
            self.frame,
            title="Edit Rule",
            rule_model=self.rule_model,
            rule_data=rule
        )
        
        if dialog.result:
            # Refresh the table to show changes
            self.update_rules_table()
            messagebox.showinfo("Success", "Rule updated successfully")

    def delete_rule(self):
        """Delete the selected rule(s)"""
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select at least one rule to delete")
            return
        
        # Confirm deletion
        if not messagebox.askyesno(
            "Confirm Delete",
            f"Delete {len(selected)} selected rule(s)? This cannot be undone."
        ):
            return
        
        # Delete each selected rule
        success_count = 0
        for item_id in selected:
            rule_id = self.rules_tree.item(item_id)['values'][0]
            if self.rule_model.delete_rule(rule_id):
                success_count += 1
        
        # Refresh the table
        self.update_rules_table()
        
        messagebox.showinfo(
            "Delete Complete",
            f"Successfully deleted {success_count} of {len(selected)} selected rule(s)"
        )

    def toggle_rule(self):
        """Toggle enabled status of selected rule(s)"""
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select at least one rule to toggle")
            return
        
        # Toggle each selected rule
        for item_id in selected:
            rule_id = self.rules_tree.item(item_id)['values'][0]
            self.rule_model.toggle_rule(rule_id)
        
        # Refresh the table to show updated status
        self.update_rules_table()

    def duplicate_rule(self):
        """Create a copy of the selected rule"""
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule to duplicate")
            return
        
        # Get the first selected item
        item = self.rules_tree.item(selected[0])
        rule_id = item['values'][0]
        
        # Get the full rule data
        original_rule = self.rule_model.get_rule_by_id(rule_id)
        if not original_rule:
            messagebox.showerror("Error", "Rule not found")
            return
        
        # Ask for new rule name
        new_name = simpledialog.askstring(
            "Duplicate Rule",
            "Enter a name for the new rule:",
            initialvalue=f"Copy of {original_rule['name']}"
        )
        
        if not new_name:
            return  # User cancelled
        
        # Create the duplicate rule
        new_rule = {
            'name': new_name,
            'condition': original_rule['condition'],
            'action': original_rule['action'],
            'severity': original_rule['severity'],
            'enabled': original_rule['enabled']
        }
        
        # Add to database
        self.rule_model.create_rule(**new_rule)
        
        # Refresh the table
        self.update_rules_table()
        messagebox.showinfo("Success", "Rule duplicated successfully")

    def test_rule(self):
        """Test the selected rule against recent events"""
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule to test")
            return
        
        # Get the first selected item
        item = self.rules_tree.item(selected[0])
        rule_id = item['values'][0]
        
        # Get the full rule data
        rule = self.rule_model.get_rule_by_id(rule_id)
        if not rule:
            messagebox.showerror("Error", "Rule not found")
            return
        
        # In a real implementation, this would test the rule against events
        # and show matching events in a dialog
        
        messagebox.showinfo(
            "Rule Test",
            f"Tested rule: {rule['name']}\n\n"
            f"Condition: {rule['condition']}\n\n"
            "This would show matching events in a real implementation."
        )

    def show_context_menu(self, event):
        """Show context menu for rules"""
        item = self.rules_tree.identify_row(event.y)
        if item:
            self.rules_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def _get_severity_label(self, severity: int) -> str:
        """Get human-readable severity label"""
        labels = {
            1: "1 - Low",
            2: "2 - Medium",
            3: "3 - High",
            4: "4 - Critical",
            5: "5 - Emergency"
        }
        return labels.get(severity, str(severity))

class RuleEditDialog:
    """Dialog for editing or creating rules"""
    def __init__(self, parent, title: str, rule_model: RuleModel, rule_data: Dict = None):
        self.parent = parent
        self.rule_model = rule_model
        self.rule_data = rule_data or {}
        self.result = None
        
        # Create dialog
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("600x500")
        self.dialog.resizable(True, True)
        
        # Result flag
        self.result = False
        
        # Create widgets
        self._create_widgets()
        
        # Populate fields if editing
        if rule_data:
            self._populate_fields()
        
        # Set focus to name field
        self.name_entry.focus_set()
        
        # Bind Enter key to save
        self.dialog.bind('<Return>', lambda e: self.save_rule())
        
        # Center the dialog
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.wait_window(self.dialog)
    
    def _create_widgets(self):
        """Create all widgets for the dialog"""
        # Main container frame
        main_frame = ttk.Frame(self.dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Name field
        ttk.Label(main_frame, text="Rule Name:").pack(anchor=tk.W, pady=(0, 5))
        self.name_entry = ttk.Entry(main_frame)
        self.name_entry.pack(fill=tk.X, pady=(0, 10))
        
        # Condition field with label and help button
        condition_frame = ttk.Frame(main_frame)
        condition_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(condition_frame, text="Condition:").pack(side=tk.LEFT, anchor=tk.W)
        
        help_btn = ttk.Button(
            condition_frame,
            text="Help",
            command=self.show_condition_help,
            width=5
        )
        help_btn.pack(side=tk.RIGHT)
        
        # Condition text area with scrollbar
        condition_container = ttk.Frame(main_frame)
        condition_container.pack(fill=tk.BOTH, expand=True)
        
        self.condition_text = tk.Text(
            condition_container,
            wrap=tk.WORD,
            font=('Consolas', 10),  # Monospace for better condition editing
            height=8
        )
        
        scrollbar = ttk.Scrollbar(
            condition_container,
            orient=tk.VERTICAL,
            command=self.condition_text.yview
        )
        self.condition_text.configure(yscrollcommand=scrollbar.set)
        
        self.condition_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Action, Severity, and Enabled fields
        options_frame = ttk.Frame(main_frame)
        options_frame.pack(fill=tk.X, pady=10)
        
        # Action
        ttk.Label(options_frame, text="Action:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.action_var = tk.StringVar(value='alert')
        action_combo = ttk.Combobox(
            options_frame,
            textvariable=self.action_var,
            values=['alert', 'block', 'notify', 'log'],
            state='readonly',
            width=15
        )
        action_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Severity
        ttk.Label(options_frame, text="Severity:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.severity_var = tk.IntVar(value=3)
        severity_combo = ttk.Combobox(
            options_frame,
            textvariable=self.severity_var,
            values=[1, 2, 3, 4, 5],
            state='readonly',
            width=5
        )
        severity_combo.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)
        
        # Enabled checkbox
        self.enabled_var = tk.BooleanVar(value=True)
        enabled_check = ttk.Checkbutton(
            options_frame,
            text="Enabled",
            variable=self.enabled_var
        )
        enabled_check.grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Save button
        save_btn = ttk.Button(
            button_frame,
            text="Save Rule",
            command=self.save_rule,
            style='Accent.TButton' if self.rule_data else None
        )
        save_btn.pack(side=tk.RIGHT, padx=5)
        
        # Cancel button
        cancel_btn = ttk.Button(
            button_frame,
            text="Cancel",
            command=self.dialog.destroy
        )
        cancel_btn.pack(side=tk.RIGHT, padx=5)
        
        # Test button (only for existing rules)
        if self.rule_data:
            test_btn = ttk.Button(
                button_frame,
                text="Test Rule",
                command=self.test_rule
            )
            test_btn.pack(side=tk.LEFT, padx=5)
        
        # Configure grid weights
        options_frame.grid_columnconfigure(1, weight=1)
    
    def _populate_fields(self):
        """Populate fields with existing rule data"""
        self.name_entry.insert(0, self.rule_data['name'])
        self.condition_text.insert(tk.END, self.rule_data['condition'])
        self.action_var.set(self.rule_data['action'])
        self.severity_var.set(self.rule_data['severity'])
        self.enabled_var.set(self.rule_data['enabled'])
    
    def save_rule(self):
        """Save the rule to the database"""
        name = self.name_entry.get().strip()
        condition = self.condition_text.get("1.0", tk.END).strip()
        action = self.action_var.get()
        severity = self.severity_var.get()
        enabled = self.enabled_var.get()
        
        # Validate inputs
        if not name:
            messagebox.showerror("Error", "Rule name is required")
            return
        
        if not condition:
            messagebox.showerror("Error", "Condition is required")
            return
        
        # Prepare rule data
        rule_data = {
            'name': name,
            'condition': condition,
            'action': action,
            'severity': severity,
            'enabled': enabled
        }
        
        # Save to database
        if self.rule_data:
            # Update existing rule
            rule_data['id'] = self.rule_data['id']
            success = self.rule_model.update_rule(**rule_data)
        else:
            # Create new rule
            success = self.rule_model.create_rule(**rule_data)
        
        if success:
            self.result = True
            self.dialog.destroy()
        else:
            messagebox.showerror("Error", "Failed to save rule")
    
    def test_rule(self):
        """Test the current rule condition"""
        condition = self.condition_text.get("1.0", tk.END).strip()
        
        if not condition:
            messagebox.showerror("Error", "Condition is empty")
            return
        
        # In a real implementation, this would test the condition against events
        messagebox.showinfo(
            "Rule Test",
            f"Tested condition:\n\n{condition}\n\n"
            "This would show matching events in a real implementation."
        )
    
    def show_condition_help(self):
        """Show help for writing rule conditions"""
        help_text = """
Rule Condition Help:

You can write conditions using event fields and operators:

Available fields:
- timestamp: Event timestamp (datetime)
- source: Event source (string)
- event_type: Type of event (string)
- severity: Severity level (1-5)
- description: Event description (string)
- ip_address: Source IP address (string)
- status: Event status (string)

Examples:
1. Simple match:
   event_type == 'Failed Login'

2. Multiple conditions:
   source == 'Firewall' AND severity >= 3

3. Pattern matching:
   description LIKE '%SQL injection%'

4. Count conditions:
   event_type == 'Failed Login' AND COUNT() > 5

5. IP address matching:
   ip_address == '192.168.1.1' OR 
   ip_address IN ('10.0.0.1', '10.0.0.2')

Note: Conditions are evaluated as Python expressions.
"""
        
        help_dialog = tk.Toplevel(self.dialog)
        help_dialog.title("Condition Help")
        help_dialog.geometry("500x400")
        
        text = tk.Text(
            help_dialog,
            wrap=tk.WORD,
            font=('Consolas', 10)
        )
        text.insert(tk.END, help_text.strip())
        text.config(state=tk.DISABLED)
        
        scrollbar = ttk.Scrollbar(
            help_dialog,
            orient=tk.VERTICAL,
            command=text.yview
        )
        text.configure(yscrollcommand=scrollbar.set)
        
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        close_btn = ttk.Button(
            help_dialog,
            text="Close",
            command=help_dialog.destroy
        )
        close_btn.pack(pady=5)