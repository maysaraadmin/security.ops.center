    def _create_rules_tab(self):
        """Create the rules tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Rules")
        
        # Configure grid
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        
        # Toolbar
        toolbar = ttk.Frame(tab)
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        
        ttk.Button(
            toolbar, 
            text="Add Rule", 
            command=self._add_rule,
            width=12
        ).pack(side="left", padx=2)
        
        ttk.Button(
            toolbar, 
            text="Edit Rule", 
            command=self._edit_rule,
            width=12
        ).pack(side="left", padx=2)
        
        ttk.Button(
            toolbar, 
            text="Delete Rule", 
            command=self._delete_rule,
            width=12
        ).pack(side="left", padx=2)
        
        ttk.Button(
            toolbar, 
            text="Import...", 
            command=self._import_rules,
            width=12
        ).pack(side="left", padx=2)
        
        ttk.Button(
            toolbar, 
            text="Export...", 
            command=self._export_rules,
            width=12
        ).pack(side="left", padx=2)
        
        # Rules table
        self.rules_table = ttk.Treeview(
            tab,
            columns=('enabled', 'id', 'name', 'type', 'severity', 'action'),
            show='headings',
            selectmode='browse'
        )
        
        # Configure columns
        self.rules_table.heading('enabled', text='', anchor='center')
        self.rules_table.heading('id', text='ID', anchor='w')
        self.rules_table.heading('name', text='Name', anchor='w')
        self.rules_table.heading('type', text='Type', anchor='w')
        self.rules_table.heading('severity', text='Severity', anchor='w')
        self.rules_table.heading('action', text='Action', anchor='w')
        
        self.rules_table.column('enabled', width=30, stretch=False, anchor='center')
        self.rules_table.column('id', width=80, stretch=False)
        self.rules_table.column('name', width=200, stretch=True)
        self.rules_table.column('type', width=100, stretch=False)
        self.rules_table.column('severity', width=80, stretch=False)
        self.rules_table.column('action', width=80, stretch=False)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(tab, orient="vertical", command=self.rules_table.yview)
        hsb = ttk.Scrollbar(tab, orient="horizontal", command=self.rules_table.xview)
        self.rules_table.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid table and scrollbars
        self.rules_table.grid(row=1, column=0, sticky="nsew")
        vsb.grid(row=1, column=1, sticky="ns")
        hsb.grid(row=2, column=0, sticky="ew")
        
        # Add double-click event
        self.rules_table.bind("<Double-1>", self._on_rule_double_click)
        
        # Populate rules
        self._populate_rules()
    
    def _create_whitelist_tab(self):
        """Create the whitelist tab."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Whitelist")
        
        # Configure grid
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        
        # Toolbar
        toolbar = ttk.Frame(tab)
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        
        # Whitelist type dropdown
        ttk.Label(toolbar, text="Type:").pack(side="left", padx=2)
        
        self.whitelist_type = tk.StringVar()
        whitelist_types = [
            'paths', 
            'processes', 
            'signed_by'
        ]
        
        type_dropdown = ttk.Combobox(
            toolbar,
            textvariable=self.whitelist_type,
            values=whitelist_types,
            state='readonly',
            width=15
        )
        type_dropdown.pack(side="left", padx=2)
        type_dropdown.set(whitelist_types[0])
        type_dropdown.bind('<<ComboboxSelected>>', self._on_whitelist_type_changed)
        
        # Add/remove buttons
        ttk.Button(
            toolbar, 
            text="Add Item", 
            command=self._add_whitelist_item,
            width=12
        ).pack(side="left", padx=2)
        
        ttk.Button(
            toolbar, 
            text="Remove Selected", 
            command=self._remove_whitelist_item,
            width=12
        ).pack(side="left", padx=2)
        
        ttk.Button(
            toolbar, 
            text="Import...", 
            command=self._import_whitelist,
            width=12
        ).pack(side="left", padx=2)
        
        ttk.Button(
            toolbar, 
            text="Export...", 
            command=self._export_whitelist,
            width=12
        ).pack(side="left", padx=2)
        
        # Whitelist items listbox
        self.whitelist_listbox = tk.Listbox(
            tab,
            selectmode='extended',
            font=('TkDefaultFont', 10)
        )
        
        # Add scrollbars
        vsb = ttk.Scrollbar(tab, orient="vertical", command=self.whitelist_listbox.yview)
        hsb = ttk.Scrollbar(tab, orient="horizontal", command=self.whitelist_listbox.xview)
        self.whitelist_listbox.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid listbox and scrollbars
        self.whitelist_listbox.grid(row=1, column=0, sticky="nsew")
        vsb.grid(row=1, column=1, sticky="ns")
        hsb.grid(row=2, column=0, sticky="ew")
        
        # Populate initial whitelist
        self._populate_whitelist()
    
    # UI Update Methods
    
    def _update_status(self):
        """Update the status display."""
        try:
            # Get status from manager
            status = self.hips_manager.get_status()
            
            # Update status indicator
            if status['running']:
                self.status_var.set("Status: Running")
                self.status_indicator.config(foreground="green")
                self.start_btn.config(text="Stop")
            else:
                self.status_var.set("Status: Stopped")
                self.status_indicator.config(foreground="red")
                self.start_btn.config(text="Start")
            
            # Update uptime
            if 'start_time' in status and status['start_time']:
                uptime_seconds = status.get('uptime', 0)
                hours = int(uptime_seconds // 3600)
                minutes = int((uptime_seconds % 3600) // 60)
                seconds = int(uptime_seconds % 60)
                self.uptime_var.set(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
            
            # Update monitoring checkboxes
            for name, var in self.monitoring_vars.items():
                var.set(status['monitoring'].get(name, False))
            
            # Update stats
            self._update_stats()
            
        except Exception as e:
            print(f"Error updating status: {e}")
    
    def _update_stats(self):
        """Update statistics display."""
        # This would be populated from actual statistics
        # For now, we'll just show some placeholder data
        self.stats_vars['file_events'].set("0")
        self.stats_vars['process_events'].set("0")
        self.stats_vars['network_events'].set("0")
        self.stats_vars['service_events'].set("0")
        self.stats_vars['high_severity'].set("0")
        self.stats_vars['medium_severity'].set("0")
        self.stats_vars['low_severity'].set("0")
    
    def _populate_rules(self):
        """Populate the rules table."""
        # Clear existing items
        for item in self.rules_table.get_children():
            self.rules_table.delete(item)
        
        # Get rules from manager
        rules = self.hips_manager.get_rules()
        
        # Add rules to table
        for rule in rules:
            self.rules_table.insert('', 'end', 
                values=(
                    '✓' if rule.get('enabled', False) else '',
                    rule.get('id', ''),
                    rule.get('name', ''),
                    rule.get('type', '').replace('_', ' ').title(),
                    rule.get('severity', '').title(),
                    rule.get('action', '').title()
                ),
                tags=('enabled' if rule.get('enabled', False) else 'disabled',)
            )
        
        # Configure tag colors
        self.rules_table.tag_configure('enabled', background='#e8f5e9')  # Light green
        self.rules_table.tag_configure('disabled', background='#ffebee')  # Light red
    
    def _populate_alerts(self):
        """Populate the alerts table."""
        # Clear existing items
        for item in self.alerts_table.get_children():
            self.alerts_table.delete(item)
        
        # Get alerts from manager
        alerts = self.hips_manager.get_alerts(limit=1000)  # Limit to 1000 most recent
        
        # Add alerts to table
        for alert in alerts:
            timestamp = datetime.fromtimestamp(alert['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            severity = alert.get('severity', 'info').title()
            rule_name = alert.get('details', {}).get('rule', {}).get('name', 'N/A')
            description = alert.get('description', '')
            
            self.alerts_table.insert('', 'end', 
                values=(timestamp, severity, rule_name, description),
                tags=(severity.lower(),)
            )
        
        # Configure tag colors
        self.alerts_table.tag_configure('high', foreground='red')
        self.alerts_table.tag_configure('medium', foreground='orange')
        self.alerts_table.tag_configure('low', foreground='blue')
        self.alerts_table.tag_configure('info', foreground='black')
    
    def _populate_whitelist(self):
        """Populate the whitelist listbox."""
        # Clear existing items
        self.whitelist_listbox.delete(0, 'end')
        
        # Get current whitelist type
        whitelist_type = self.whitelist_type.get()
        if not whitelist_type:
            return
        
        # Get whitelist items
        items = self.hips_manager.get_whitelist(whitelist_type)
        
        # Add items to listbox
        for item in sorted(items):
            self.whitelist_listbox.insert('end', item)
