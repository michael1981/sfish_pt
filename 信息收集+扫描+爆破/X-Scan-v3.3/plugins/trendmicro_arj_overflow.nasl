#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(17213);
 script_cve_id("CVE-2005-0533");
 script_bugtraq_id(12643);
 script_xref(name:"OSVDB", value:"14133");
 if ( defined_func("script_xref") ) 

 script_version("$Revision: 1.8 $");
 name["english"] = "Trend Micro VSAPI ARJ Handling Heap Overflow";
 script_name(english:name["english"]);
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Trend Micro engine which 
is vulnerable to a heap overflow in the ARJ handling functions.

An attacker may exploit this flaw to bypass virus protection 
altogether and execute arbitrary code on the remote host. To exploit
this flaw, an attacker would need to submit a malformed ARJ archive to
a process on the remote host and wait for the antivirus engine to scan
it." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2d903ac" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the Trend Micro engine version 7.510 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 summary["english"] = "Checks the version of the remote Trend Micro engine";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc."); 
 family["english"] = "Windows"; 
 script_family(english:family["english"]);
 script_dependencies("trendmicro_installed.nasl");
 script_require_keys("Antivirus/TrendMicro/trendmicro_engine_version");
 exit(0);
}

version = get_kb_item("Antivirus/TrendMicro/trendmicro_engine_version");
if ( ! version ) exit(0);
if ( int(version) < 7510 ) security_hole(0);
