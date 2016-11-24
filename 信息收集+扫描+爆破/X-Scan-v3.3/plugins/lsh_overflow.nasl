#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: Haggis <haggis@learningshophull.co.uk>
# To: bugtraq@securityfocus.com
# Subject: Remote root vuln in lsh 1.4.x
# Date: Fri, 19 Sep 2003 13:01:24 +0000
# Message-Id: <200309191301.24607.haggis@haggis.kicks-ass.net>


include("compat.inc");

if(description)
{
 script_id(11843);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0826");
 script_bugtraq_id(8655);
 script_xref(name:"OSVDB", value:"11744");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:041");
 
 script_name(english:"LSH Daemon lshd Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"You are running a version of LSH (a free replacement for SSH) which is
older than 1.5.3

Versions older than 1.5.3 are vulnerable to a buffer overflow which
may allow an attacker to gain a root shell on this host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-09/0310.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-09/0326.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to lsh 1.5.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for the remote SSH version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#


port = get_kb_item("Services/ssh");
if(!port)port = 22;

banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

if(egrep(pattern:".*lshd[-_](0\..*|1\.[0-4]\.|1\.5\.[0-2])", string:banner, icase:TRUE)) security_hole(port);
