# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(18382);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200505-18");
 script_cve_id("CVE-2005-1740");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200505-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200505-18
(Net-SNMP: fixproc insecure temporary file creation)


    The fixproc application of Net-SNMP creates temporary files with
    predictable filenames.
  
Impact

    A malicious local attacker could exploit a race condition to change the
    content of the temporary files before they are executed by fixproc,
    possibly leading to the execution of arbitrary code. A local attacker
    could also create symbolic links in the temporary files directory,
    pointing to a valid file somewhere on the filesystem. When fixproc is
    executed, this would result in the file being overwritten.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Net-SNMP users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/net-snmp-5.2.1-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1740');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200505-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200505-18] Net-SNMP: fixproc insecure temporary file creation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Net-SNMP: fixproc insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/net-snmp", unaffected: make_list("ge 5.2.1-r1"), vulnerable: make_list("lt 5.2.1-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
