#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 
# MS-SQL Client Tool
# 
# This software provides a command-line interface for interacting with Microsoft SQL Server
# using the TDS protocol.
#
# Author: errooe
#
# Reference for:
#  - MS-TDS (Tabular Data Stream) Protocol
#  - MC-SQLR (SQL Server Resolution Protocol)
#

import sys
import logging
import argparse
import configparser
import os
import cmd
import time
from typing import Optional, List, Dict, Any, Tuple

try:
    import pyodbc
    PYODBC_AVAILABLE = True
except ImportError:
    PYODBC_AVAILABLE = False

try:
    from impacket import version
    from impacket.examples import logger
    from impacket.examples.utils import parse_target
    from impacket import tds
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False
    print("Impacket library not found. Please install it using: pip install impacket")
    sys.exit(1)


class SQLSHELL(cmd.Cmd):
    def __init__(self, sql_instance, options=None):
        """
        Initialize the SQL shell with connection parameters
        
        Args:
            sql_instance: SQL Server instance to connect to
            options: Additional connection options
        """
        cmd.Cmd.__init__(self)
        self.sql = sql_instance
        self.prompt = f'SQL> '
        self.intro = '[*] SQL shell connected. Type help or ? for available commands'
        self.options = options
        self.tid = 0
        self.rows = 0
        self.sql.timeout = 5
        self.default_db = None
        self.default_language = None
        self.printReplies = True
        self.logger = logging.getLogger('mssql_client')

    def connect_to_db(self) -> bool:
        """Establish connection to the database"""
        try:
            self.sql.connect()
            self.default_db = self.sql.getServerName()
            self.default_language = self.sql.getServerLanguage()
            return True
        except Exception as e:
            self.logger.error(f"Connection failed: {str(e)}")
            return False

    def do_help(self, line):
        """Show available commands"""
        print("""
        Available commands:
        help                            - Show this help menu
        use <database>                  - Connect to a specific database
        sql <SQL command>               - Execute SQL command
        xp_cmdshell <command>           - Execute command through xp_cmdshell
        sp_start_job <job>              - Execute a SQL Server job
        enable_xp_cmdshell              - Enable xp_cmdshell stored procedure
        disable_xp_cmdshell             - Disable xp_cmdshell stored procedure
        enum_db                         - Enumerate databases
        enum_links                      - Enumerate linked servers
        enum_impersonation              - Enumerate impersonation privileges
        enum_logins                     - Enumerate login accounts
        enum_users                      - Enumerate database users
        enum_tables                     - Enumerate tables
        columns <table>                 - Show columns for specified table
        exit                            - Exit the shell
        """)

    def do_sql(self, sql):
        """Execute SQL command"""
        if not sql:
            print("[!] SQL statement required")
            return
        
        try:
            self.tid += 1
            self.sql.sql_query(sql, self.tid)
            self.rows = self.sql.getLastRowCount()
            if self.printReplies:
                print(f"[*] Executed SQL query successfully, {self.rows} rows affected")
        except Exception as e:
            print(f"[!] ERROR executing SQL: {str(e)}")

    def do_use(self, db):
        """Connect to a specific database"""
        if not db:
            print("[!] Database name required")
            return
            
        try:
            self.tid += 1
            self.sql.sql_query(f"USE {db}", self.tid)
            self.sql.printReplies()
            self.sql.printRows()
            print(f"[*] Switched to database {db}")
        except Exception as e:
            print(f"[!] ERROR switching database: {str(e)}")

    def do_enum_db(self, line):
        """Enumerate databases"""
        try:
            self.tid += 1
            self.sql.sql_query("SELECT name FROM master..sysdatabases", self.tid)
            self.sql.printRows()
        except Exception as e:
            print(f"[!] ERROR enumerating databases: {str(e)}")

    def do_enum_tables(self, line):
        """Enumerate tables in current database"""
        try:
            self.tid += 1
            self.sql.sql_query("SELECT name FROM sysobjects WHERE xtype='U'", self.tid)
            self.sql.printRows()
        except Exception as e:
            print(f"[!] ERROR enumerating tables: {str(e)}")

    def do_columns(self, table):
        """Show columns for specified table"""
        if not table:
            print("[!] Table name required")
            return
            
        try:
            self.tid += 1
            self.sql.sql_query(f"SELECT name, xtype FROM syscolumns WHERE id=OBJECT_ID('{table}')", self.tid)
            self.sql.printRows()
        except Exception as e:
            print(f"[!] ERROR retrieving columns: {str(e)}")

    def do_enum_links(self, line):
        """Enumerate linked servers"""
        try:
            self.tid += 1
            self.sql.sql_query("EXEC sp_linkedservers", self.tid)
            self.sql.printRows()
        except Exception as e:
            print(f"[!] ERROR enumerating linked servers: {str(e)}")

    def do_enum_users(self, line):
        """Enumerate database users"""
        try:
            self.tid += 1
            self.sql.sql_query("SELECT name, createdate, updatedate FROM sysusers", self.tid)
            self.sql.printRows()
        except Exception as e:
            print(f"[!] ERROR enumerating users: {str(e)}")

    def do_enum_logins(self, line):
        """Enumerate login accounts"""
        try:
            self.tid += 1
            self.sql.sql_query("SELECT name, createdate, updatedate, accdate, password FROM syslogins", self.tid)
            self.sql.printRows()
        except Exception as e:
            print(f"[!] ERROR enumerating logins: {str(e)}")

    def do_enum_impersonation(self, line):
        """Enumerate impersonation privileges"""
        try:
            self.tid += 1
            self.sql.sql_query("SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'", self.tid)
            self.sql.printRows()
        except Exception as e:
            print(f"[!] ERROR enumerating impersonation privileges: {str(e)}")

    def do_enable_xp_cmdshell(self, line):
        """Enable xp_cmdshell stored procedure"""
        try:
            commands = [
                "EXEC sp_configure 'show advanced options', 1",
                "RECONFIGURE",
                "EXEC sp_configure 'xp_cmdshell', 1", 
                "RECONFIGURE"
            ]
            for cmd in commands:
                self.tid += 1
                self.sql.sql_query(cmd, self.tid)
            print("[*] xp_cmdshell enabled")
        except Exception as e:
            print(f"[!] ERROR enabling xp_cmdshell: {str(e)}")

    def do_disable_xp_cmdshell(self, line):
        """Disable xp_cmdshell stored procedure"""
        try:
            commands = [
                "EXEC sp_configure 'xp_cmdshell', 0",
                "RECONFIGURE",
                "EXEC sp_configure 'show advanced options', 0",
                "RECONFIGURE"
            ]
            for cmd in commands:
                self.tid += 1
                self.sql.sql_query(cmd, self.tid)
            print("[*] xp_cmdshell disabled")
        except Exception as e:
            print(f"[!] ERROR disabling xp_cmdshell: {str(e)}")

    def do_xp_cmdshell(self, command):
        """Execute command through xp_cmdshell"""
        if not command:
            print("[!] Command required")
            return
            
        try:
            self.tid += 1
            self.sql.sql_query(f"EXEC master..xp_cmdshell '{command}'", self.tid)
            self.sql.printRows()
        except Exception as e:
            print(f"[!] ERROR executing xp_cmdshell: {str(e)}")

    def do_sp_start_job(self, job):
        """Execute a SQL Server job"""
        if not job:
            print("[!] Job name required")
            return
            
        try:
            self.tid += 1
            self.sql.sql_query(f"EXEC master..sp_start_job '{job}'", self.tid)
            self.sql.printReplies()
            self.sql.printRows()
        except Exception as e:
            print(f"[!] ERROR executing job: {str(e)}")

    def do_exit(self, line):
        """Exit the shell"""
        print("[*] Exiting...")
        if self.sql:
            self.sql.disconnect()
        return True


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="MS-SQL Client Tool")
    
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    
    connection_group = parser.add_argument_group('Connection')
    connection_group.add_argument('-host', action='store', help='Target host or IP address')
    connection_group.add_argument('-port', action='store', default='1433', help='Target port (default: 1433)')
    
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('-db', action='store', help='Database to connect to')
    auth_group.add_argument('-windows-auth', action='store_true', help='Use Windows Authentication')
    auth_group.add_argument('-username', action='store', help='Username')
    auth_group.add_argument('-password', action='store', help='Password')
    auth_group.add_argument('-domain', action='store', help='Domain name')
    auth_group.add_argument('-hashes', action='store', help='NTLM hashes (LM:NT format)')
    
    execution_group = parser.add_argument_group('Execution')
    execution_group.add_argument('-sql', action='store', help='SQL query to execute')
    execution_group.add_argument('-file', action='store', help='SQL script file to execute')
    execution_group.add_argument('-query-timeout', action='store', type=int, default=5, help='Query timeout in seconds (default: 5)')
    
    return parser.parse_args()


def main():
    """Main function to run the MS-SQL client"""
    print(f"MS-SQL Client Tool v1.0")
    
    args = parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
    
    if not args.host:
        print("[!] Host parameter required")
        sys.exit(1)
    
    if not args.username and not args.windows_auth:
        print("[!] Authentication method required (username or windows-auth)")
        sys.exit(1)
    
    domain = ''
    username = ''
    password = ''
    
    if args.domain:
        domain = args.domain
    
    if args.username:
        username = args.username
    
    if args.password:
        password = args.password
    
    if args.hashes:
        try:
            lm_hash, nt_hash = args.hashes.split(':')
        except ValueError:
            print("[!] Hashes must be in LM:NT format")
            sys.exit(1)
    else:
        lm_hash = ''
        nt_hash = ''
    
    try:
        ms_sql = tds.MSSQL(args.host, int(args.port))
        
        if args.windows_auth:
            ms_sql.connect_windows(domain, username, password, lm_hash, nt_hash)
        else:
            ms_sql.connect(username, password)
        
        shell = SQLSHELL(ms_sql, args)
        
        if args.db:
            shell.do_use(args.db)
        
        if args.sql:
            shell.do_sql(args.sql)
            ms_sql.disconnect()
            return
        
        if args.file:
            try:
                with open(args.file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('--'):
                            shell.do_sql(line)
                ms_sql.disconnect()
                return
            except Exception as e:
                print(f"[!] ERROR reading SQL file: {str(e)}")
                ms_sql.disconnect()
                return
        
        shell.cmdloop()
    
    except Exception as e:
        print(f"[!] ERROR: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()