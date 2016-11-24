# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-19.xml
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
 script_id(20263);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200511-19");
 script_cve_id("CVE-2005-3785");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200511-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200511-19
(eix: Insecure temporary file creation)


    Eric Romang discovered that eix creates a temporary file with a
    predictable name. eix creates a temporary file in /tmp/eix.*.sync where
    * is the process ID of the shell running eix.
  
Impact

    A local attacker can watch the process list and determine the process
    ID of the shell running eix while the "emerge --sync" command is
    running, then create a link from the corresponding temporary file to a
    system file, which would result in the file being overwritten with the
    rights of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All eix users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose app-portage/eix
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3785');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200511-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200511-19] eix: Insecure temporary file creation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'eix: Insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-portage/eix", unaffected: make_list("ge 0.5.0_pre2", "rge 0.3.0-r2"), vulnerable: make_list("lt 0.5.0_pre2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
