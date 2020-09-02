function FindProxyForURL(url,host)
{
//PROXY SERVER VARIABLES - PERU PROXY PAC FILE 17/04/2019
var thishost=myIpAddress();
var targetip=dnsResolve(host);
var VTE_Proxy="PROXY lavteproxy.myintranet.local:8080";
var GDC_Proxy="PROXY augdcproxy.myintranet.local:8085";
var PER_Proxy="PROXY pelipsgi01.myintranet.local:8085";
var Go_Direct="DIRECT";

var VTE_Hosts=(isInNet(thishost, "10.26.0.0","255.255.192.0"));
var Peru_Hosts =(isInNet(thishost, "10.51.0.0", "255.255.0.0") ||
						isInNet(thishost, "10.52.0.0", "255.255.0.0") ||
						isInNet(thishost, "10.53.0.0", "255.255.0.0") ||
						isInNet(thishost, "10.243.0.0", "255.255.0.0") ||
						isInNet(thishost, "10.54.0.0", "255.255.0.0"));
var Global_Hosts=(isInNet(thishost, "10.0.0.0", "255.0.0.0") ||
                        isInNet(thishost, "172.16.0.0", "255.240.0.0") ||
                        isInNet(thishost, "192.168.0.0", "255.255.0.0"));
var Ext_Hosted=(dnsDomainIs(host, "mmgnet") ||
                        shExpMatch(host, "*.zinifex.net")||
                        dnsDomainIs(host, "century")||
                        dnsDomainIs(host, "centurykb"));
var Office_365=(shExpMatch(host, "*.office365.com") ||
                shExpMatch(host, "*.microsoftonline.com") ||
                shExpMatch(host, "*.outlook.office.com") ||
                shExpMatch(host, "*.broadcast.skype.com") ||
                shExpMatch(host, "*.lync.com") ||
                shExpMatch(host, "*.mail.protection.outlook.com") ||
                shExpMatch(host, "*.manage.office.com") ||
                shExpMatch(host, "*.onenote.officeapps.live.com") ||
                shExpMatch(host, "*.msappproxy.net") ||
                shExpMatch(host, "*.portal.cloudappsecurity.com") ||
                shExpMatch(host, "*.protection.office.com") ||
                shExpMatch(host, "*.protection.outlook.com") ||
                shExpMatch(host, "*.sharepoint.com") ||
                shExpMatch(host, "*.skypeforbusiness.com") ||
                shExpMatch(host, "*.teams.microsoft.com") ||
                shExpMatch(host, "*broadcast.officeapps.live.com") ||
                shExpMatch(host, "*excel.officeapps.live.com") ||
                shExpMatch(host, "*onenote.officeapps.live.com") ||
                shExpMatch(host, "*powerpoint.officeapps.live.com") ||
                shExpMatch(host, "*rtc.officeapps.live.com") ||
                shExpMatch(host, "*shared.officeapps.live.com") ||
                shExpMatch(host, "*view.officeapps.live.com") ||
                shExpMatch(host, "*visio.officeapps.live.com") ||
                shExpMatch(host, "*word-edit.officeapps.live.com") ||
                shExpMatch(host, "*word-view.officeapps.live.com") ||
                shExpMatch(host, "*.msftidentity.com") ||
                shExpMatch(host, "*.msidentity.com") ||
                dnsDomainIs(host, "a.config.skype.com") ||
                dnsDomainIs(host, "account.activedirectory.windowsazure.com") ||
                dnsDomainIs(host, "accounts.accesscontrol.windows.net") ||
                dnsDomainIs(host, "accounts.office.net") ||
                dnsDomainIs(host, "admin.microsoft.com") ||
                dnsDomainIs(host, "agent.office.net") ||
                dnsDomainIs(host, "autologon.microsoftazuread-sso.com") ||
                dnsDomainIs(host, "b.config.skype.com") ||
                dnsDomainIs(host, "broadcast.skype.com") ||
                dnsDomainIs(host, "clientconfig.microsoftonline-p.net") ||
                dnsDomainIs(host, "clientlog.portal.office.com") ||
                dnsDomainIs(host, "config.edge.skype.com") ||
                dnsDomainIs(host, "delve.office.com") ||
                dnsDomainIs(host, "graph.microsoft.com") ||
                dnsDomainIs(host, "graph.windows.net") ||
                dnsDomainIs(host, "hip.microsoftonline-p.net") ||
                dnsDomainIs(host, "home.office.com") ||
                dnsDomainIs(host, "login.microsoft.com") ||
                dnsDomainIs(host, "login.microsoftonline-p.com") ||
                dnsDomainIs(host, "login.windows.net") ||
                dnsDomainIs(host, "manage.office.com") ||
                dnsDomainIs(host, "nexus.microsoftonline-p.com") ||
                dnsDomainIs(host, "nexus.officeapps.live.com") ||
                dnsDomainIs(host, "nexusrules.officeapps.live.com") ||
                dnsDomainIs(host, "office.live.com") ||
                dnsDomainIs(host, "outlook.office.com") ||
                dnsDomainIs(host, "outlook.office365.com") ||
                dnsDomainIs(host, "portal.office.com") ||
                dnsDomainIs(host, "secure.aadcdn.microsoftonline-p.com") ||
                dnsDomainIs(host, "smtp.office365.com") ||
                dnsDomainIs(host, "teams.microsoft.com") ||
                dnsDomainIs(host, "www.office.com"));

// End of Variable Definition and Start of Logic

if (
     Office_365
   ) return "DIRECT";

// Intranet Sites Hosted Externally
						if  (
                                Ext_Hosted && VTE_Hosts
                                ) return VTE_Proxy ;
						if  (
                                Ext_Hosted && Peru_Hosts
                                ) return PER_Proxy ;
                        if  (
                                Ext_Hosted && Global_Hosts
                                ) return GDC_Proxy ;

// Bypass for Private Nets
                else if (
                        isPlainHostName(host) ||
                        (dnsResolve(host) == "127.0.0.1")||
                        (host == "localhost")||
                        (host == "127.0.0.1") ||
                        isInNet(targetip, "127.0.0.0", "255.255.255.0") ||
                        isInNet(targetip, "10.0.0.0", "255.0.0.0") ||
                        isInNet(targetip, "172.16.0.0", "255.240.0.0") ||
                        isInNet(targetip, "192.168.0.0", "255.255.0.0") ||
// Bypass for MMG Public Net
                        isInNet(targetip, "103.10.48.0", "255.255.254.0") ||
// Bypass for Global_Mineman Application
                        isInNet(targetip, "125.7.48.99", "255.255.255.255")||
                        isInNet(targetip, "125.7.100.131", "255.255.255.255")||
// Bypass for HP service Portal
                        shExpMatch(host, "*.serviceportal.hp.com") ||
                        shExpMatch(host, "138.35.238.*") ||
						dnsDomainIs(host, "apj-p.svcs.hp.com") ||
// Bypass for kingdee.mmr.com
                        (host == "113.28.164.78") ||
                        dnsDomainIs(host, "kingdee.mmr.com") ||
// Bypass Internal Domains and URLs
                        dnsDomainIs(host, ".myintranet.local") ||
                        dnsDomainIs(host, ".myextranet.local") ||
                        dnsDomainIs(host, ".myexternal.local") ||
//                        dnsDomainIs(host, ".zinifex.net") ||
//                        dnsDomainIs(host, ".oxiana.com.au") ||
                        dnsDomainIs(host, ".lasbambas.local") ||
// Bypass for Worleyparsons.com SVR21387474
						(host == "61.14.33.15") ||
						dnsDomainIs (host, "auperblu.worleyparsons.com") ||
// Bypass for Bpc-574.boardpad.com BoardPad ICM21428940
						(host == "213.212.86.121") ||
						dnsDomainIs (host, "bpc-574.boardpad.com")
                ) return Go_Direct;

// Check Source Addresses
// NEW Vientiane Networks
        else if (
                        VTE_Hosts
                ) return VTE_Proxy ;
 //PERU networks
		else if (
                        Peru_Hosts
                ) return PER_Proxy ;
// Global Networks
        else if (
                        Global_Hosts
                ) return GDC_Proxy ;

        else
                 return Go_Direct;
} 
