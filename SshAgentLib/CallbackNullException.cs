using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace dlech.SshAgentLib
{
  /// <summary>
  /// Indicates that a callback is required but it
  /// has not been assigned a method yet
  /// </summary>
  /// <remarks>
  /// Agent.ConfirmUserPermissionCallback must be assigned a method before
  /// calling AddKey with a key that has a confirm constraint
  /// KeyFormatter.GetPassphraseCallbackMethod must be assigned a method before
  /// attempting to deserialize an encrypted key
  /// </remarks>
  public class CallbackNullException : Exception
  {

  }
}
