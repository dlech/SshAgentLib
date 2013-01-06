using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using dlech.SshAgentLib;

namespace dlech.SshAgentLib
{
  public class KeyWrapper
  {
    private ISshKey mKey;

    public bool Confirm
    {
      get
      {
        return mKey.HasConstraint(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_CONFIRM);
      }
    }

    public bool Lifetime
    {
      get
      {
        return mKey.HasConstraint(Agent.KeyConstraintType.SSH_AGENT_CONSTRAIN_LIFETIME);
      }
    }

    public string Type
    {
      get
      {
        return mKey.Algorithm.GetIdentifierString();
      }
    }

    public int Size
    {
      get
      {
        return mKey.Size;
      }
    }

    public string Fingerprint
    {
      get
      {
        return mKey.GetMD5Fingerprint().ToHexString();
      }
    }

    public string Comment
    {
      get
      {
        return mKey.Comment;
      }
    }
    
    public KeyWrapper(ISshKey aKey)
    {
      mKey = aKey;
    }

    public ISshKey GetKey()
    {
      return mKey;
    }

  }
}
