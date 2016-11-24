
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-9721
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(41017);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-9721: drupal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-9721 (drupal)");
 script_set_attribute(attribute: "description", value: "Equipped with a powerful blend of features, Drupal is a Content Management
System written in PHP that can support a variety of websites ranging from
personal weblogs to large community-driven websites.  Drupal is highly
configurable, skinnable, and secure.

-
Update Information:

Fixes SA-CORE-2009-008  [9]http://drupal.org/node/579482    Remember to log in
to
your site as the admin user before upgrading this package. After upgrading the
package, browse to [10]http://host/drupal/update.php to run the upgrade script.
Multiple vulnerabilities and weaknesses were discovered in Drupal.  OpenID
association cross site request forgeries    The OpenID module in Drupal 6 allow
s
users to create an account or log into a Drupal site using one or more OpenID
identities.    The core OpenID module does not correctly implement Form API for
the form that allows one to link user accounts with OpenID identifiers. A
malicious user is therefore able to use cross site request forgeries to add
attacker controlled OpenID identities to existing accounts. These OpenID
identities can then be used to gain access to the affected accounts.    This
issue affects Drupal 6.x only.  OpenID impersonation    The OpenID module is no
t
a compliant implementation of the OpenID Authentication 2.0 specification. An
implementation error allows a user to access the account of another user when
they share the same OpenID 2.0 provider.    This issue affects Drupal 6.x only.
File upload    File uploads with certain extensions are not correctly processed
by the File API. This may lead to the creation of files that are executable by
Apache. The .htaccess that is saved into the files directory by Drupal should
normally prevent execution. The files are only executable when the server is
configured to ignore the directives in the .htaccess file.    This issue affect
s
Drupal 6.x only.  Session fixation    Drupal doesn't regenerate the session ID
when an anonymous user follows the one time login link used to confirm email
addresses and reset forgotten passwords. This enables a malicious user to fix
and reuse the session id of a victim under certain circumstances.    This issue
affects Drupal 5.x only.  Versions affected        * Drupal 6.x before version
6.14.      * Drupal 5.x before version 5.20.    Solution    Install the latest
version:        * If you are running Drupal 6.x then upgrade to Drupal 6.14.

Update information :

* If you are running Drupal 5.x then upgrade to Drupal 5.20.    If you are
unable to upgrade immediately, you can apply a patch to secure your installatio
n
until you are able to do a proper upgrade. Theses patches fix the security
vulnerabilities, but do not contain other fixes which were released in Drupal
6.14 or Drupal 5.20.        * To patch Drupal 6.13 use SA-
CORE-2009-008-6.13.patch.      * To patch Drupal 5.19 use SA-
CORE-2009-008-5.19.patch.    Important note: Some users using OpenID might not
be able to use the existing OpenID associations to login after the upgrade.
These users should use the one time login via password recovery to get access t
o
their user account and re-add desired associations. These users likely had
issues with OpenID logins prior to the upgrade.  Reported by    The session
fixation issue was reported by Noel Sharpe.  OpenID impersonation was reported
by Robert Metcalf.  OpenID association CSRF was reported by Heine Deelstra (*).
The file upload issue was reported by Heine Deelstra (*).    (*) Member of the
Drupal security team  Fixed by    The session fixation issue was fixed by Jakub
Suchy.  The OpenID and file upload issues were fixed by Heine Deelstra.  Contac
t
The security team for Drupal can be reached at security at drupal.org or via th
e
form at [11]http://drupal.org/contact.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the drupal package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"drupal-6.14-1.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
