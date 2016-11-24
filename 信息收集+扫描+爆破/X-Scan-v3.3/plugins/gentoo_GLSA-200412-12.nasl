# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-12.xml
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
 script_id(15993);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200412-12");
 script_cve_id("CVE-2004-1152");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200412-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200412-12
(Adobe Acrobat Reader: Buffer overflow vulnerability)


    A buffer overflow has been discovered in the email processing of
    Adobe Acrobat Reader. This flaw exists in the mailListIsPdf function,
    which checks if the input file is an email message containing a PDF
    file.
  
Impact

    A remote attacker could send the victim a specially-crafted email
    and PDF attachment, which would trigger the buffer overflow and
    possibly lead to the execution of arbitrary code with the permissions
    of the user running Adobe Acrobat Reader.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Adobe Acrobat Reader users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/acroread-5.10"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-1152');
script_set_attribute(attribute: 'see_also', value: 'http://www.adobe.com/support/techdocs/331153.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200412-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200412-12] Adobe Acrobat Reader: Buffer overflow vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Adobe Acrobat Reader: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/acroread", unaffected: make_list("ge 5.10"), vulnerable: make_list("lt 5.10")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
