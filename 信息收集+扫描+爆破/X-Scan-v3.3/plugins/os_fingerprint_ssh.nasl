#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25287);
  script_version("$Revision: 1.20 $");

  name["english"] = "OS Identification : SSH";
  script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based
on the SSH banner." );
 script_set_attribute(attribute:"description", value:
"This script attempts to identify the Operating System type 
and version by looking at the SSH banner returned by the 
remote server." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 
  summary["english"] = "Determines the remote operating system";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  family["english"] = "General";
  script_family(english:family["english"]);
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  exit(0);
}



ports = get_kb_list("Services/ssh");
if ( isnull(ports) )
 ports = make_list(22);
else 
 ports = make_list(ports);

port = ports[0];
if ( ! get_port_state(port) ) exit(0);


banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);

set_kb_item(name:"Host/OS/SSH/Fingerprint", value:banner);

confidence = 95;
#
# If SSH is not running on port 22, decrease the confidence level
# as it might be a port forwarded somewhere else
#
if ( port != 22  || max_index(ports) > 1 ) confidence -= 20;

if ( banner == "SSH-2.0-xxxxxxx" )
{
 set_kb_item(name:"Host/OS/SSH", value:"Fortinet Firewall");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-Sun_SSH_1\.0\.1"  )
{
 set_kb_item(name:"Host/OS/SSH", value:"Solaris 9");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-Sun_SSH_1\.1"  )
{
 set_kb_item(name:"Host/OS/SSH", value:"Solaris 10");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~  "^SSH-2\.0-Sun_SSH_1\.0$" )
{
 set_kb_item(name:"Host/OS/SSH", value:"Solaris 8");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_3\.5p1 FreeBSD" )
{
 set_kb_item(name:"Host/OS/SSH", value:'FreeBSD 4.10');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_3\.8\.1p1 FreeBSD" )
{
 confidence -= 10; # Multiple matches
 set_kb_item(name:"Host/OS/SSH", value:'FreeBSD 5.3\nFreeBSD 5.4\nFreeBSD 5.5');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_4\.2p1 FreeBSD-" )
{
 confidence -= 10; # Multiple matches
 set_kb_item(name:"Host/OS/SSH", value:'FreeBSD 6.0\nFreeBSD 6.1');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_4\.5p1 FreeBSD-" )
{
 confidence -= 10; # Multiple matches
 set_kb_item(name:"Host/OS/SSH", value:'FreeBSD 6.2\nFreeBSD 6.3\nFreeBSD 7.0');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_3\.8\.1p1.*ubuntu")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Ubuntu Linux 4.10 (warty)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_3\.9p1.*ubuntu")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Ubuntu Linux 5.04 (hoary)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_4\.1p1.*ubuntu")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Ubuntu Linux 5.10 (breezy)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_4\.2p1.*ubuntu")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Ubuntu Linux 6.06 (dapper)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_4\.3p2.*ubuntu")
{
 confidence -= 5;
 set_kb_item(name:"Host/OS/SSH", value:'Linux Kernel 2.6 on Ubuntu Linux 6.10 (edgy)\nLinux Kernel 2.6 on Unbuntu Linux 7.04 (feisty)');
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_4\.6p1 Debian-5ubuntu")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Ubuntu Linux 7.10 (gutsy)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_4\.7p1 Debian-8ubuntu")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Ubuntu Linux 8.04 (hardy)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_1\.2\.3.* Debian")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.2 on Debian 2.2 (potato)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_3\.4p1 Debian")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.2 on Debian 3.0 (woody)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_3\.8\.1p1 Debian.*sarge")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.4 on Debian 3.1 (sarge)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-.*-OpenSSH_4\.3p2 Debian")
{
 set_kb_item(name:"Host/OS/SSH", value:"Linux Kernel 2.6 on Debian 4.0 (etch)");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner == "SSH-2.0-Unknown" )
{
 set_kb_item(name:"Host/OS/SSH", value:"NetEnforcer Application Bandwidth Manager");
 set_kb_item(name:"Host/OS/SSH/Type", value:"packet-shaper");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:15);
}
else if ( banner =~ "SSH-.* SSH Secure Shell Tru64 UNIX" )
{
 # SSH.com SSH only exist for Tru64 5.1
 set_kb_item(name:"Host/OS/SSH", value:"Tru64 Unix 5.1");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:confidence);
}
else if ( banner =~ "SSH-2\.0-mpSSH_0\.0\.1" )
{
 set_kb_item(name:"Host/OS/SSH", value:"HP Integrated Lights Out Board");
 set_kb_item(name:"Host/OS/SSH/Type", value:"embedded");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:75);
}
else if ( banner =~ "^SSH-2\.0-XPSSH" )
{
 set_kb_item(name:"Host/OS/SSH", value:"Enterasys XP Switch");
 set_kb_item(name:"Host/OS/SSH/Type", value:"switch");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:45);
}
# SSH-2.0-3.2.0 F-SECURE SSH - Process Software MultiNet
# SSH-1.99-3.1.0 F-SECURE SSH - Process Software TCPware
# SSH-2.0-3.2.0 SSH Secure Shell OpenVMS V5.5 
else if (banner =~ "^(SSH-(1\.99|2\.0)-.* Process Software (MultiNet|TCPware)|SSH-(1\.99|2\.0)-.* SSH Secure Shell OpenVMS)")
{
 set_kb_item(name:"Host/OS/SSH", value:"OpenVMS");
 set_kb_item(name:"Host/OS/SSH/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/SSH/Confidence", value: 76);
}
else if ( banner =~ "SSH-[0-9.]+-Cisco-1\.25" )
{
 set_kb_item(name:"Host/OS/SSH", value:'CISCO IOS 12\nCISCO PIX');
 set_kb_item(name:"Host/OS/SSH/Type", value:"router");
 set_kb_item(name:"Host/OS/SSH/Confidence", value:69);
}
