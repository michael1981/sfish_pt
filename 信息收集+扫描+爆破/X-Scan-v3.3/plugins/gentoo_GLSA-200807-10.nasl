# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200807-10.xml
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
 script_id(33556);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200807-10");
 script_cve_id("CVE-2007-5626");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200807-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200807-10
(Bacula: Information disclosure)


    Matthijs Kooijman reported that the "make_catalog_backup" script uses
    the MySQL password as a command line argument when invoking other
    programs.
  
Impact

    A local attacker could list the processes on the local machine when the
    script is running to obtain the MySQL password. Note: The password
    could also be disclosed via network sniffing attacks when the script
    fails, in which case it would be sent via cleartext e-mail.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    A warning about this issue has been added in version 2.4.1, but the
    issue is still unfixed. We advise not to use the make_catalog_backup
    script, but to put all MySQL parameters into a dedicated file readable
    only by the user running Bacula.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5626');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200807-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200807-10] Bacula: Information disclosure');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Bacula: Information disclosure');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-backup/bacula", unaffected: make_list("ge 2.4.1"), vulnerable: make_list("lt 2.4.1")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
