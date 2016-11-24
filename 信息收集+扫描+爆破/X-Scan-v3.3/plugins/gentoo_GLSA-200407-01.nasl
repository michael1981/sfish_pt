# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-01.xml
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
 script_id(14534);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200407-01");
 script_cve_id("CVE-2004-0655");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200407-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200407-01
(Esearch: Insecure temp file handling)


    The eupdatedb utility uses a temporary file (/tmp/esearchdb.py.tmp) to
    indicate that the eupdatedb process is running. When run, eupdatedb
    checks to see if this file exists, but it does not check to see if it
    is a broken symlink. In the event that the file is a broken symlink,
    the script will create the file pointed to by the symlink, instead of
    printing an error and exiting.
  
Impact

    An attacker could create a symlink from /tmp/esearchdb.py.tmp to a
    nonexistent file (such as /etc/nologin), and the file will be created
    the next time esearchdb is run.
  
Workaround

    There is no known workaround at this time. All users should upgrade to
    the latest available version of esearch.
  
');
script_set_attribute(attribute:'solution', value: '
    All users should upgrade to the latest available version of esearch, as
    follows:
    # emerge sync
    # emerge -pv ">=app-portage/esearch-0.6.2"
    # emerge ">=app-portage/esearch-0.6.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0655');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200407-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200407-01] Esearch: Insecure temp file handling');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Esearch: Insecure temp file handling');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-portage/esearch", unaffected: make_list("ge 0.6.2"), vulnerable: make_list("le 0.6.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
