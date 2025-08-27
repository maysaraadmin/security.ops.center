"""
EDR Rule Editor
Provides a GUI for managing detection rules.
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Callable, Dict, Any, Optional
from .rule_manager import RuleManager
import json
import yaml

class RuleEditor(tk.Toplevel):
    """A dialog for editing EDR detection rules."""
    
    def __init__(self, parent, rule_manager: RuleManager, rule_id: str = None, on_save: Callable = None):
        """Initialize the rule editor.
        
        Args:
            parent: Parent window
            rule_manager: Instance of RuleManager
            rule_id: ID of rule to edit, or None for new rule
            on_save: Callback when rule is saved
        """
        super().__init__(parent)
        self.rule_manager = rule_manager
        self.on_save = on_save
        self.rule_id = rule_id
        self.rule_data = {}
        
        # Set up the window
        self.title("Edit Detection Rule" if rule_id else "New Detection Rule")
        self.geometry("800x600")
        self.resizable(True, True)
        
        # Load rule data if editing
        if rule_id:
            rule = rule_manager.get_rule(rule_id)
            if rule:
                self.rule_data = rule.copy()
        
        # Set default values for new rule
        if not self.rule_data:
            self.rule_data = {
                'id': '',
                'name': '',
                'description': '',
                'severity': 'medium',
                'enabled': True,
                'type': 'process',
                'tags': [],
                'condition': {},
                'action': 'alert'
            }
        
        # Create UI
        self._create_widgets()
        self._layout_widgets()
        
        # Populate fields if editing
        if self.rule_id:
            self._populate_fields()
    
    def _create_widgets(self):
        """Create the UI widgets."""
        # Main container
        self.main_frame = ttk.Frame(self, padding="10")
        
        # Basic info frame
        info_frame = ttk.LabelFrame(self.main_frame, text="Rule Information", padding=10)
        
        # Basic fields
        ttk.Label(info_frame, text="Rule ID:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.id_var = tk.StringVar(value=self.rule_data.get('id', ''))
        self.id_entry = ttk.Entry(info_frame, textvariable=self.id_var, width=40)
        self.id_entry.grid(row=0, column=1, sticky=tk.W, pady=2, padx=5)
        
        ttk.Label(info_frame, text="Name:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.name_var = tk.StringVar(value=self.rule_data.get('name', ''))
        ttk.Entry(info_frame, textvariable=self.name_var, width=40).grid(
            row=1, column=1, sticky=tk.W, pady=2, padx=5, columnspan=2)
        
        ttk.Label(info_frame, text="Description:").grid(row=2, column=0, sticky=tk.NW, pady=2)
        self.desc_text = tk.Text(info_frame, width=60, height=4, wrap=tk.WORD)
        self.desc_text.grid(row=2, column=1, sticky=tk.W, pady=2, padx=5, columnspan=2)
        
        # Rule settings
        settings_frame = ttk.LabelFrame(self.main_frame, text="Rule Settings", padding=10)
        
        ttk.Label(settings_frame, text="Type:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.type_var = tk.StringVar(value=self.rule_data.get('type', 'process'))
        type_combo = ttk.Combobox(
            settings_frame, 
            textvariable=self.type_var,
            values=['process', 'network', 'file', 'registry', 'memory'],
            state='readonly',
            width=15
        )
        type_combo.grid(row=0, column=1, sticky=tk.W, pady=2, padx=5)
        
        ttk.Label(settings_frame, text="Severity:").grid(row=0, column=2, sticky=tk.W, pady=2, padx=10)
        self.severity_var = tk.StringVar(value=self.rule_data.get('severity', 'medium'))
        severity_combo = ttk.Combobox(
            settings_frame,
            textvariable=self.severity_var,
            values=['low', 'medium', 'high', 'critical'],
            state='readonly',
            width=10
        )
        severity_combo.grid(row=0, column=3, sticky=tk.W, pady=2, padx=5)
        
        self.enabled_var = tk.BooleanVar(value=self.rule_data.get('enabled', True))
        ttk.Checkbutton(
            settings_frame, 
            text="Enabled", 
            variable=self.enabled_var
        ).grid(row=0, column=4, sticky=tk.W, pady=2, padx=10)
        
        # Condition editor
        cond_frame = ttk.LabelFrame(self.main_frame, text="Conditions", padding=10)
        
        # Use a text widget for raw JSON/YAML editing of conditions
        self.cond_text = tk.Text(cond_frame, width=70, height=10, wrap=tk.NONE)
        self.cond_text.grid(row=0, column=0, sticky='nsew')
        
        # Add scrollbars
        y_scroll = ttk.Scrollbar(cond_frame, orient='vertical', command=self.cond_text.yview)
        x_scroll = ttk.Scrollbar(cond_frame, orient='horizontal', command=self.cond_text.xview)
        self.cond_text.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        
        y_scroll.grid(row=0, column=1, sticky='ns')
        x_scroll.grid(row=1, column=0, sticky='ew')
        
        # Action settings
        action_frame = ttk.LabelFrame(self.main_frame, text="Actions", padding=10)
        
        ttk.Label(action_frame, text="Action:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.action_var = tk.StringVar(value=self.rule_data.get('action', 'alert'))
        action_combo = ttk.Combobox(
            action_frame,
            textvariable=self.action_var,
            values=['alert', 'block', 'quarantine', 'log'],
            state='readonly',
            width=15
        )
        action_combo.grid(row=0, column=1, sticky=tk.W, pady=2, padx=5)
        
        # Tags
        tags_frame = ttk.LabelFrame(self.main_frame, text="Tags", padding=10)
        
        self.tags_var = tk.StringVar()
        self.tags_entry = ttk.Entry(tags_frame, textvariable=self.tags_var, width=40)
        self.tags_entry.grid(row=0, column=0, sticky=tk.W, pady=2, padx=5)
        self.tags_entry.insert(0, ', '.join(self.rule_data.get('tags', [])))
        
        # Buttons
        button_frame = ttk.Frame(self.main_frame)
        
        self.save_btn = ttk.Button(
            button_frame, 
            text="Save", 
            command=self._on_save,
            style='Accent.TButton' if not self.rule_id else ''
        )
        self.save_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame, 
            text="Cancel", 
            command=self.destroy
        ).pack(side=tk.LEFT, padx=5)
        
        if self.rule_id:
            ttk.Button(
                button_frame,
                text="Delete",
                command=self._on_delete,
                style='Danger.TButton'
            ).pack(side=tk.RIGHT, padx=5)
        
        # Store references
        self.info_frame = info_frame
        self.settings_frame = settings_frame
        self.cond_frame = cond_frame
        self.action_frame = action_frame
        self.tags_frame = tags_frame
        self.button_frame = button_frame
    
    def _layout_widgets(self):
        """Layout the widgets in the window."""
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Grid layout for main containers
        self.info_frame.pack(fill=tk.X, pady=(0, 10))
        self.settings_frame.pack(fill=tk.X, pady=(0, 10))
        self.cond_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.action_frame.pack(fill=tk.X, pady=(0, 10))
        self.tags_frame.pack(fill=tk.X, pady=(0, 10))
        self.button_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Configure grid weights
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(2, weight=1)  # Make condition editor expand
        
        # Bind events
        self.bind('<Return>', lambda e: self._on_save())
        self.bind('<Escape>', lambda e: self.destroy())
    
    def _populate_fields(self):
        """Populate form fields with rule data."""
        # Set description
        self.desc_text.delete('1.0', tk.END)
        self.desc_text.insert('1.0', self.rule_data.get('description', ''))
        
        # Set condition JSON
        condition = self.rule_data.get('condition', {})
        try:
            cond_str = json.dumps(condition, indent=2)
            self.cond_text.delete('1.0', tk.END)
            self.cond_text.insert('1.0', cond_str)
        except Exception as e:
            messagebox.showerror("Error", f"Invalid condition format: {e}")
    
    def _get_rule_data(self) -> Dict[str, Any]:
        """Get rule data from form fields."""
        rule = {
            'id': self.id_var.get().strip(),
            'name': self.name_var.get().strip(),
            'description': self.desc_text.get('1.0', tk.END).strip(),
            'type': self.type_var.get(),
            'severity': self.severity_var.get(),
            'enabled': self.enabled_var.get(),
            'action': self.action_var.get(),
            'tags': [t.strip() for t in self.tags_var.get().split(',') if t.strip()],
            'condition': self._parse_condition()
        }
        
        # Preserve any additional fields from original rule
        for key in self.rule_data:
            if key not in rule and not key.startswith('_'):
                rule[key] = self.rule_data[key]
        
        return rule
    
    def _parse_condition(self) -> Dict[str, Any]:
        """Parse condition from text input."""
        cond_str = self.cond_text.get('1.0', tk.END).strip()
        if not cond_str:
            return {}
        
        try:
            # Try JSON first
            return json.loads(cond_str)
        except json.JSONDecodeError:
            try:
                # Try YAML
                return yaml.safe_load(cond_str) or {}
            except Exception as e:
                messagebox.showerror("Error", f"Invalid condition format: {e}")
                raise ValueError(f"Invalid condition: {e}")
    
    def _validate_rule(self, rule: Dict[str, Any]) -> bool:
        """Validate the rule data."""
        if not rule['id']:
            messagebox.showerror("Error", "Rule ID is required")
            return False
        
        if not rule['name']:
            messagebox.showerror("Error", "Rule name is required")
            return False
        
        if not rule.get('condition'):
            messagebox.showerror("Error", "At least one condition is required")
            return False
        
        return True
    
    def _on_save(self, event=None):
        """Handle save button click."""
        try:
            rule = self._get_rule_data()
            
            if not self._validate_rule(rule):
                return
            
            # Update or add the rule
            if self.rule_id and self.rule_id != rule['id']:
                # ID was changed, remove old rule
                self.rule_manager.delete_rule(self.rule_id)
                self.rule_id = rule['id']
            
            # Add or update the rule
            if self.rule_manager.get_rule(rule['id']):
                self.rule_manager.update_rule(rule['id'], rule)
            else:
                self.rule_manager.add_rule(rule)
            
            # Call the save callback if provided
            if self.on_save:
                self.on_save(rule)
            
            self.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save rule: {e}")
    
    def _on_delete(self):
        """Handle delete button click."""
        if messagebox.askyesno(
            "Delete Rule",
            f"Are you sure you want to delete rule '{self.rule_data.get('name', self.rule_id)}'?",
            icon='warning'
        ):
            self.rule_manager.delete_rule(self.rule_id)
            if self.on_save:
                self.on_save(None)  # Indicate deletion
            self.destroy()


class RuleManagerUI(ttk.Frame):
    """A UI for managing EDR detection rules."""
    
    def __init__(self, parent, rule_manager: RuleManager, **kwargs):
        """Initialize the rule manager UI."""
        super().__init__(parent, **kwargs)
        self.rule_manager = rule_manager
        self._create_widgets()
        self._layout_widgets()
        self._load_rules()
    
    def _create_widgets(self):
        """Create the UI widgets."""
        # Toolbar
        self.toolbar = ttk.Frame(self)
        
        self.add_btn = ttk.Button(
            self.toolbar,
            text="Add Rule",
            command=self._on_add_rule,
            style='Accent.TButton'
        )
        
        self.import_btn = ttk.Button(
            self.toolbar,
            text="Import Rules",
            command=self._on_import_rules
        )
        
        self.export_btn = ttk.Button(
            self.toolbar,
            text="Export Selected",
            command=self._on_export_rules
        )
        
        # Rules treeview
        columns = ('enabled', 'id', 'name', 'type', 'severity', 'action', 'description')
        self.tree = ttk.Treeview(
            self,
            columns=columns,
            show='headings',
            selectmode='extended'
        )
        
        # Configure columns
        self.tree.heading('enabled', text='Enabled')
        self.tree.heading('id', text='ID')
        self.tree.heading('name', text='Name')
        self.tree.heading('type', text='Type')
        self.tree.heading('severity', text='Severity')
        self.tree.heading('action', text='Action')
        self.tree.heading('description', text='Description')
        
        self.tree.column('enabled', width=60, anchor='center')
        self.tree.column('id', width=100, anchor='w')
        self.tree.column('name', width=150, anchor='w')
        self.tree.column('type', width=80, anchor='center')
        self.tree.column('severity', width=80, anchor='center')
        self.tree.column('action', width=100, anchor='center')
        self.tree.column('description', width=300, anchor='w')
        
        # Add scrollbars
        vsb = ttk.Scrollbar(self, orient='vertical', command=self.tree.yview)
        hsb = ttk.Scrollbar(self, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Store references
        self.vsb = vsb
        self.hsb = hsb
    
    def _layout_widgets(self):
        """Layout the widgets."""
        # Toolbar
        self.toolbar.pack(fill=tk.X, pady=(0, 5))
        self.add_btn.pack(side=tk.LEFT, padx=2)
        self.import_btn.pack(side=tk.LEFT, padx=2)
        self.export_btn.pack(side=tk.LEFT, padx=2)
        
        # Treeview with scrollbars
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Bind double-click to edit
        self.tree.bind('<Double-1>', self._on_edit_rule)
        
        # Bind right-click for context menu
        self.tree.bind('<Button-3>', self._on_right_click)
    
    def _load_rules(self):
        """Load rules into the treeview."""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add rules
        for rule in self.rule_manager.get_rules():
            self.tree.insert('', 'end', values=(
                '✓' if rule.get('enabled', False) else '',
                rule.get('id', ''),
                rule.get('name', ''),
                rule.get('type', ''),
                rule.get('severity', '').capitalize(),
                rule.get('action', '').capitalize(),
                rule.get('description', '')[:100] + '...' if rule.get('description', '') else ''
            ), tags=('enabled' if rule.get('enabled', False) else 'disabled'))
        
        # Configure tag colors
        self.tree.tag_configure('enabled', background='#f0fff0')  # Light green
        self.tree.tag_configure('disabled', background='#fff0f0')  # Light red
    
    def _on_add_rule(self):
        """Handle add rule button click."""
        editor = RuleEditor(self, self.rule_manager, on_save=self._on_rule_saved)
        self.wait_window(editor)
    
    def _on_edit_rule(self, event=None):
        """Handle edit rule (double-click)."""
        selected = self.tree.selection()
        if not selected:
            return
        
        # Get the rule ID from the selected item
        item = self.tree.item(selected[0])
        rule_id = item['values'][1]  # ID is the second column
        
        # Open the editor
        editor = RuleEditor(
            self,
            self.rule_manager,
            rule_id=rule_id,
            on_save=self._on_rule_saved
        )
        self.wait_window(editor)
    
    def _on_rule_saved(self, rule):
        """Callback when a rule is saved or deleted."""
        self._load_rules()
    
    def _on_import_rules(self):
        """Handle import rules button click."""
        file_path = filedialog.askopenfilename(
            title="Import Rules",
            filetypes=[
                ("YAML files", "*.yaml;*.yml"),
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return
        
        try:
            # Try to load the file
            with open(file_path, 'r', encoding='utf-8') as f:
                if file_path.lower().endswith(('.yaml', '.yml')):
                    rules = yaml.safe_load(f)
                else:  # Assume JSON
                    rules = json.load(f)
            
            # Process the rules
            if isinstance(rules, list):
                count = 0
                for rule in rules:
                    if self.rule_manager.add_rule(rule):
                        count += 1
                messagebox.showinfo("Import Complete", f"Successfully imported {count} rules.")
            elif isinstance(rules, dict):
                if self.rule_manager.add_rule(rules):
                    messagebox.showinfo("Import Complete", "Successfully imported 1 rule.")
            
            # Refresh the view
            self._load_rules()
            
        except Exception as e:
            messagebox.showerror("Import Error", f"Failed to import rules: {e}")
    
    def _on_export_rules(self):
        """Handle export rules button click."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select one or more rules to export.")
            return
        
        # Get selected rules
        rules = []
        for item_id in selected:
            item = self.tree.item(item_id)
            rule_id = item['values'][1]  # ID is the second column
            rule = self.rule_manager.get_rule(rule_id)
            if rule:
                rules.append(rule)
        
        if not rules:
            return
        
        # Ask for output file
        file_path = filedialog.asksaveasfilename(
            title="Export Rules",
            defaultextension=".yaml",
            filetypes=[
                ("YAML files", "*.yaml"),
                ("JSON files", "*.json"),
            ]
        )
        
        if not file_path:
            return
        
        try:
            # Save the rules
            with open(file_path, 'w', encoding='utf-8') as f:
                if file_path.lower().endswith('.json'):
                    json.dump(rules if len(rules) > 1 else rules[0], f, indent=2)
                else:  # YAML
                    yaml.dump(rules if len(rules) > 1 else rules[0], f, default_flow_style=False)
            
            messagebox.showinfo("Export Complete", f"Successfully exported {len(rules)} rules to {file_path}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export rules: {e}")
    
    def _on_right_click(self, event):
        """Handle right-click event for context menu."""
        # Select the item that was right-clicked
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            
            # Create context menu
            menu = tk.Menu(self, tearoff=0)
            menu.add_command(label="Edit", command=self._on_edit_rule)
            menu.add_command(label="Toggle Enable/Disable", command=self._on_toggle_enable)
            menu.add_separator()
            menu.add_command(label="Delete", command=self._on_delete_rule)
            
            # Show the menu
            menu.tk_popup(event.x_root, event.y_root)
    
    def _on_toggle_enable(self):
        """Toggle enable/disable for selected rules."""
        selected = self.tree.selection()
        if not selected:
            return
        
        for item_id in selected:
            item = self.tree.item(item_id)
            rule_id = item['values'][1]  # ID is the second column
            
            # Toggle the enabled state
            rule = self.rule_manager.get_rule(rule_id)
            if rule:
                self.rule_manager.enable_rule(rule_id, not rule.get('enabled', False))
        
        # Refresh the view
        self._load_rules()
    
    def _on_delete_rule(self):
        """Delete selected rules."""
        selected = self.tree.selection()
        if not selected:
            return
        
        # Ask for confirmation
        if not messagebox.askyesno(
            "Delete Rules",
            f"Are you sure you want to delete {len(selected)} selected rules?",
            icon='warning'
        ):
            return
        
        # Delete the rules
        count = 0
        for item_id in selected:
            item = self.tree.item(item_id)
            rule_id = item['values'][1]  # ID is the second column
            if self.rule_manager.delete_rule(rule_id):
                count += 1
        
        # Refresh the view
        self._load_rules()
        
        # Show result
        messagebox.showinfo("Delete Complete", f"Successfully deleted {count} rules.")


if __name__ == "__main__":
    # Example usage
    root = tk.Tk()
    root.title("EDR Rule Manager")
    root.geometry("1000x600")
    
    # Create a rule manager instance
    rule_manager = RuleManager("rules")
    
    # Create the UI
    app = RuleManagerUI(root, rule_manager)
    app.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    # Run the application
    root.mainloop()
