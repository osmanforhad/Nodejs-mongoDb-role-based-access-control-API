const AccessControl = require("accesscontrol");
const ac = new AccessControl();

exports.roles = function () {
  /**
   * Define Access Control for
   * BASIC
   *
   * Role
   */
  ac.grant("basic");
  _readOwn("profile");
  _updateOwn("profile");

  /**
   * Define Access Control for
   * SuperVisor
   *
   * Role
   */
  ac.grant("supervisor");
  _extend("basic");
  _readAny("profile");

  /**
   * Define Access Control for
   * Admin
   *
   * Role
   */
  ac.grant("admin");
  _extend("basic");
  _extend("supervisor");
  _updateAny("profile");
  _deleteAny("profile");

  return ac;
};
