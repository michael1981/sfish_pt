#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14711);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2004-0807", "CVE-2004-0808");
 script_bugtraq_id(11156);
 script_xref(name:"OSVDB", value:"9916");
 script_xref(name:"OSVDB", value:"9917");

 script_name(english:"Samba < 3.0.7 Multiple Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The remote Samba server, according to its version number, is vulnerable 
to a denial of service.

There is a bug in the remote smbd ASN.1 parsin, which may allow an attacker
to cause a denial of service attack against the remote host by sending
a specially crafted ASN.1 packet during the authentication request which
may make the newly-spawned smbd process run into an infinite loop. By
establishing multiple connections and sending such packets, an attacker
may consume all the CPU and memory of the remote host, thus crashing it
remotely.

Another bug may allow an attacker to crash the remote nmbd process by
sending a malformed NetBIOS packet." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Samba 3.0.7" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );


script_end_attributes();

 script_summary(english: "checks samba version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english: "Denial of Service");
 script_dependencie("smb_nativelanman.nasl");
 script_require_keys("SMB/NativeLanManager");
 exit(0);
}

#
# The script code starts here
#

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 if(ereg(pattern:"Samba 3\.0\.[0-6][^0-9]*$",
 	 string:lanman))security_warning(139);
}
