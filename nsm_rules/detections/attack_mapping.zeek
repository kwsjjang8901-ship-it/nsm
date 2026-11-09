module NSM;

export {
    redef record Notice::Info += {
        attack: string &optional &log;
    };

    const attack_map: table[Notice::Type] of string = {
        [Port_Scan]            = "T1046",        
        [Host_Scan]            = "T1018",        
		[SQL_Injection]        = "T1190",        
        [Webshell_Access]      = "T1505.003",    
        [NTLM_Spray]           = "T1110.003",    
        [SMB_Admin_Share]      = "T1021.002",    
        [RDP_Lateral]          = "T1021.001",    
        [SSH_Lateral]          = "T1021.004",    
        [HTTP_Beaconing]       = "T1071.001",    
        [DNS_Tunneling]        = "T1071.004, T1572", 
        [Encrypted_C2]         = "T1573.002",    
        [Exfil_Large_Transfer] = "T1041",        
        [Exfil_Volume_Aggregate] = "T1041",      
        [Correlated_KillChain] = "T1021.002,T1041",  
		[Exfil_DNS]            = "T1048.003",    
        [Exfil_Web_Upload]     = "T1567.002",    
        [DGA_Domain]           = "T1568.002"     
    } &redef;
}

hook Notice::policy(n: Notice::Info)
    {
    if ( n?$attack )
        return;
    if ( n$note in attack_map )
        n$attack = attack_map[n$note];
    }
