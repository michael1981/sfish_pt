# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200709-04.xml
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
 script_id(26094);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200709-04");
 script_cve_id("CVE-2007-4462");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200709-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200709-04
(po4a: Insecure temporary file creation)


    The po4a development team reported a race condition in the gettextize()
    function when creating the file "/tmp/gettextization.failed.po".
  
Impact

    A local attacker could perform a symlink attack, possibly overwriting
    files with the permissions of the user running po4a.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All po4a users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/po4a-0.32-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4462');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200709-04] po4a: Insecure temporary file creation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'po4a: Insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/po4a", unaffected: make_list("ge 0.32-r1"), vulnerable: make_list("lt 0.32-r1")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
