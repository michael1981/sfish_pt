# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-03.xml
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
 script_id(14489);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200405-03");
 script_cve_id("CVE-2004-1876");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200405-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200405-03
(ClamAV VirusEvent parameter vulnerability)


    The VirusEvent parameter in the clamav.conf configuration file allows
    to specify a system command to run whenever a virus is found. This
    system command can make use of the "%f" parameter which is replaced by
    the name of the file infected. The name of the file scanned is under
    control of the attacker and is not sufficiently checked. Version 0.70
    of clamav disables the use of the "%f" parameter.
  
Impact

    Sending a virus with a malicious file name can result in execution of
    arbirary system commands with the rights of the antivirus process.
    Since clamav is often associated to mail servers for email scanning,
    this attack can be used remotely.
  
Workaround

    You should not use the "%f" parameter in your VirusEvent configuration.
  
');
script_set_attribute(attribute:'solution', value: '
    All users of Clam AntiVirus should upgrade to the latest stable
    version:
    # emerge sync
    # emerge -pv ">=app-antivirus/clamav-0.70"
    # emerge ">=app-antivirus/clamav-0.70"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.clamav.net/');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1876');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200405-03] ClamAV VirusEvent parameter vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV VirusEvent parameter vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.70"), vulnerable: make_list("lt 0.70")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
