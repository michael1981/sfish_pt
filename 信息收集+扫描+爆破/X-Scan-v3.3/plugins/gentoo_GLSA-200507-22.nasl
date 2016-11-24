# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-22.xml
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
 script_id(19324);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200507-22");
 script_cve_id("CVE-2005-2449");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200507-22 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200507-22
(sandbox: Insecure temporary file handling)


    The Gentoo Linux Security Audit Team discovered that the sandbox
    utility was vulnerable to multiple TOCTOU (Time of Check, Time of Use)
    file creation race conditions.
  
Impact

    Local users may be able to create or overwrite arbitrary files with the
    permissions of the root user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All sandbox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-apps/sandbox-1.2.11"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2449');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200507-22.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200507-22] sandbox: Insecure temporary file handling');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'sandbox: Insecure temporary file handling');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "sys-apps/sandbox", unaffected: make_list("ge 1.2.11"), vulnerable: make_list("lt 1.2.11")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
