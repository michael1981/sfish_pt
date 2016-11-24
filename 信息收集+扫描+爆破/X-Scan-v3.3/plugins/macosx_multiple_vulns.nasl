#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description) {
 script_id(12257);
 script_version("$Revision: 1.17 $");
 script_cve_id("CVE-2004-0171", "CVE-2004-0430", "CVE-2004-0485", "CVE-2004-0513", "CVE-2004-0514",
               "CVE-2004-0515", "CVE-2004-0516", "CVE-2004-0517", "CVE-2004-0518");
 script_bugtraq_id(10268, 10271, 10432);
 script_xref(name:"OSVDB", value:"5762");
 script_xref(name:"OSVDB", value:"8434");
 script_xref(name:"OSVDB", value:"8435");
 script_xref(name:"OSVDB", value:"8436");
 script_xref(name:"OSVDB", value:"8437");
 script_xref(name:"OSVDB", value:"8438");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0004");

 script_name(english:"Mac OS X < 10.3.4 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update which fixes a security
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of MacOS which is older than
10.3.4. 

Versions older than 10.3.4 contain several flaws which may allow an
attacker to execute arbitrary commands on the remote system with root
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=300667" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2004/May/msg00005.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MacOS X 10.3.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Various flaws in MacOS X");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("os_fingerprint.nasl");
 script_require_keys("Host/OS");
 exit(0);
}

#

# The Operating system is actually very detailed, because we can read
# its exact version using NTP or RendezVous
os = get_kb_item("Host/OS");
if ( ! os || "Mac OS X" >!< os ) exit(0);

if ( egrep(pattern:"Mac OS X 10\.([01]\.|3\.[0-3])", string:os) )
	security_hole(0);

