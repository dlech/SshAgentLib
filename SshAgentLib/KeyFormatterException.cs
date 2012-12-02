using System;

namespace dlech.SshAgentLib
{
  public class KeyFormatterException : Exception
  {
    public KeyFormatterException() : base() { }

    public KeyFormatterException(string aMessage) : base(aMessage) { }

    public KeyFormatterException(string aMessage, Exception aInnerException) :
      base(aMessage, aInnerException) { }
  }
}
