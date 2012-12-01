using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace dlech.SshAgentLib
{
  /// <summary>
  /// Common interface of Agent and AgentClient
  /// </summary>
  public interface IAgent
  {

    bool AddKey(ISshKey aKey);

    bool RemoveKey(ISshKey aKey);

    bool RemoveAllKeys(SshVersion aVersion);

    bool ListKeys(SshVersion aVersion, out ICollection<ISshKey> aKeyCollection);

    bool Lock(byte[] aPassphrase);

    bool Unlock(byte[] aPassphrase);

  }

  public static class IAgentExt
  {
    public static bool AddKeyFromFile(this IAgent aAgent, string aFileName,
      KeyFormatter.GetPassphraseCallback aGetPassPhraseCallback,
      ICollection<Agent.KeyConstraint> aConstraints = null)
    {
      string firstLine;
      using (var fileReader = File.OpenText(aFileName)) {
        firstLine = fileReader.ReadLine();
      }
      var formatter = KeyFormatter.GetFormatter(firstLine);
      formatter.GetPassphraseCallbackMethod = aGetPassPhraseCallback;
      var key = formatter.DeserializeFile(aFileName);
      if (aConstraints != null) {
        foreach (var constraint in aConstraints) {
          key.AddConstraint(constraint);
        }
      }
      return aAgent.AddKey(key);
    }

    public static void RemoveAllKeys(this IAgent aAgent)
    {
      foreach (SshVersion version in Enum.GetValues(typeof(SshVersion))) {
        aAgent.RemoveAllKeys(version);
      }
    }

    public static ICollection<ISshKey> GetAllKeys(this IAgent aAgent)
    {
      List<ISshKey> allKeysList = new List<ISshKey>();
      ICollection<ISshKey> versionList;
      foreach (SshVersion version in Enum.GetValues(typeof(SshVersion))) {
        var success = aAgent.ListKeys(version, out versionList);
        if (version == SshVersion.SSH2 && !success) {
          throw new Exception("GetAllKeys Failed");
        }
        allKeysList.AddRange(versionList);
      }
      return allKeysList;
    }

  }
}
