#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(12114);
 script_version("$Revision: 1.16 $");

 script_cve_id(
  "CVE-2000-0562",
  "CVE-2002-0237",
  "CVE-2002-0956",
  "CVE-2002-0957",
  "CVE-2004-0193",
  "CVE-2004-2125",
  "CVE-2004-2126"
 );
 script_bugtraq_id(1389, 4025, 4950, 9513, 9514, 9752);
 script_xref(name:"IAVA", value:"2004-A-0003");
 script_xref(name:"IAVA", value:"2004-A-0004");
 script_xref(name:"IAVA", value:"2004-A-5003");
 script_xref(name:"OSVDB", value:"2039");
 script_xref(name:"OSVDB", value:"3740");
 script_xref(name:"OSVDB", value:"4699");
 script_xref(name:"OSVDB", value:"4700");
 script_xref(name:"OSVDB", value:"4701");
 script_xref(name:"OSVDB", value:"4702");
 script_xref(name:"OSVDB", value:"4704");
 script_xref(name:"OSVDB", value:"8701");

 script_name(english:"ISS BlackICE Multiple Remote Vulnerabilities");
 script_summary(english:"ISS BlackICE Vulnerable version detection");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The firewall running on the remote host has multiple buffer\n",
     "overflow vulnerabilities."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "ISS BlackICE is a personal Firewall/IDS for windows Desktops.\n",
     "Several remote holes have been found in the product.  An attacker,\n",
     "exploiting these flaws, would be able to either crash the remote\n",
     "firewall/IDS service or execute code on the target machine.\n\n",
     "According to the remote version number, the remote host is vulnerable\n",
     "to at least one remote overflow."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.eeye.com/html/Research/Advisories/AD20040226.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.eeye.com/html/Research/Advisories/AD20040318.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of BlackICE."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_dependencies("blackice_configs.nasl");
 script_require_keys("SMB/BlackICE/Version");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
myread = get_kb_item("SMB/BlackICE/Version");
if ( ! myread ) exit(0);


# what does the logfile format look like:
# ---------- BLACKD.LOG
# [25]Fri, 19 Mar 2004 09:58:20: BlackICE Product Version :               7.0.ebf

if (strstr(myread, "BlackICE Product Version"))  {
    # all versions 7.0 eba through ebh and 3.6 ebr through ecb 
    if (egrep(string:myread, pattern:"BlackICE Product Version.*(7\.0\.eb[a-h]|3\.6\.e(b[r-z]|c[ab]))")) {
        # do a warning for smb bug
        mywarning = string(
"According to the remote version number, the remote host is vulnerable
to a bug wherein a malformed SMB packet will allow the attacker to execute
arbitrary code on the target system.");
    port = kb_smb_transport();
    if (!port) port = 139;
    security_hole(port:port, extra:mywarning);
    }


    # all versions prior to 7.0.ebl and 3.6.ecf
    if ( (egrep(string:myread, pattern:"BlackICE Product Version.*[0-6]\.[0-9]\.[a-z][a-z][a-z]")) ||
    (egrep(string:myread, pattern:"BlackICE Product Version.*7\.0\.([a-d][a-z][a-z]|e(a[a-z]|b[a-h]))")) ) {
                mywarning = string(
"According to the remote version number, the remote host is vulnerable
to a bug wherein a malformed ICQ packet will allow the attacker to execute
arbitrary code on the target system.");
    port = kb_smb_transport();
    if (!port) port = 139;
    security_hole(port:port, extra:mywarning);
    }


    # only certain versions which have a default config issue
    # VULN VERSION:
    # 7.0 eb[j-m]
    # 3.6 ec[d-g]
    # 3.6 cc[d-g]

    if (egrep(string:myread, pattern:"BlackICE Product Version.*(7\.0\.eb[j-m]|3\.6\.(ec[d-g]|cc[d-g]))")) {
        #warning for misconfiguration
        mywarning = string(
"Nessus detected a version of BlackICE with insecure default settings.");
    port = kb_smb_transport();
    if (!port) port = 139;
    security_hole(port:port, extra:mywarning);
    }

}

