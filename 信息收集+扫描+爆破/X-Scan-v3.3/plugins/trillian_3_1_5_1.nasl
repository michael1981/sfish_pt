#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25148);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-2418");
  script_bugtraq_id(23781);
  script_xref(name:"OSVDB", value:"35720");

  script_name(english:"Trillian < 3.1.5.1 XMPP Decoding Heap Overflow");
  script_summary(english:"Checks version number of Trillian");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an instant messaging application which is susceptible
to a heap overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Trillian installed on the remote host contains a buffer
overflow vulnerability which can be triggered when decoding a malformed
XMPP (eXtensible Messaging and Presence Protocol) message. 

To exploit this flaw, an attacker would need to send a specially crafted
XMPP message to a user of this program, thus causing arbitrary code 
execution." );
 script_set_attribute(attribute:"see_also", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-07-06" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Trillian 3.1.5.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("trillian_installed.nasl");
  script_require_keys("SMB/Trillian/Version");

  exit(0);
}


ver = get_kb_item("SMB/Trillian/Version");
# Trillian > 3.1 is affected
if (ver && ver =~ "^3\.1\.([0-4]\.|5\.0)" )
  security_hole(get_kb_item("SMB/transport"));
