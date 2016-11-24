# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-02.xml
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
 script_id(17676);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200504-02");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200504-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200504-02
(Sylpheed, Sylpheed-claws: Buffer overflow on message display)


    Sylpheed and Sylpheed-claws fail to properly handle messages
    containing attachments with MIME-encoded filenames.
  
Impact

    An attacker can send a malicious email message which, when
    displayed, would cause the program to crash, potentially allowing the
    execution of arbitrary code with the privileges of the user running the
    software.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Sylpheed users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/sylpheed-1.0.4"
    All Sylpheed-claws users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/sylpheed-claws-1.0.4"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://sylpheed.good-day.net/#changes');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200504-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200504-02] Sylpheed, Sylpheed-claws: Buffer overflow on message display');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Sylpheed, Sylpheed-claws: Buffer overflow on message display');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-client/sylpheed-claws", unaffected: make_list("ge 1.0.4"), vulnerable: make_list("lt 1.0.4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "mail-client/sylpheed", unaffected: make_list("ge 1.0.4"), vulnerable: make_list("lt 1.0.4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
