# BinSentry AI-AGENT Debugger

<br>
<div align=center>
  <img width="15%" height="10%" alt="icon" src="https://github.com/user-attachments/assets/b052e3ae-e125-4e3f-9879-2e828a7d8f41" />
</div>
<br><br>
<div align=center>

[![Contributors](https://img.shields.io/github/contributors/binsentry/binsentry?color=2ea44f&logo=github)](https://github.com/lyshark/binsentry/graphs/contributors)
[![Email Support](https://img.shields.io/badge/Contact-admin@lyshark.com-0099ff?logo=gmail)](mailto:admin@lyshark.com)
[![Release Download](https://img.shields.io/github/downloads/lyshark/binsentry/total?color=orange&logo=windows)](https://github.com/lyshark/binsentry/releases/tag/binsentry)

[![Python 3.x](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://github.com/lyshark/binsentry)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64dbg-lightgrey?logo=windows)](https://github.com/lyshark/binsentry)
[![binsentry Version](https://img.shields.io/github/v/tag/lyshark/binsentry?label=Version&sort=semver&color=success)](https://github.com/lyshark/binsentry/releases)

[![GitHub Stars](https://img.shields.io/github/stars/lyshark/binsentry?style=social)](https://github.com/lyshark/binsentry/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/lyshark/binsentry?style=social)](https://github.com/lyshark/binsentry/fork)
[![License](https://img.shields.io/github/license/lyshark/binsentry)](https://github.com/lyshark/binsentry/blob/main/LICENSE)

</div>

Sentinel is a binary debugging engine designed for AI agents and intelligent scenarios. It encapsulates the complete process debugging capability as an HTTP+JSON standardized interface, allowing agents to directly drive reverse analysis, vulnerability mining, malicious sample analysis, data tracing, and other reverse tasks like calling a regular API, maximizing the speed of security experts.

## Quick Start

Users may install the corresponding debugging engine toolkit via pip:

```python
pip install binsentry
```

The following Python snippet demonstrates basic API invocation to connect to the local BinSentry service, create a debug session for a target Windows executable, and start execution control.

```python
from BinSentry import *

if __name__ == "__main__":
    # Configure connection parameters for local BinSentry service
    config = Config(
        address="127.0.0.1",
        port=6891,
        api_key="45d3552b12b12cdf2c831344311cf81e"
    )
    # Initialize BinSentry client instance
    client = BinSentryClient(config=config)

    # Print server connection information
    print("config:", client.config.server_addr)
    # Query current running status of debugging engine
    print(client.status())

    # Create a new debug session for target win32 executable
    dbg = client.debug("c://win32.exe")
    print(dbg)

    # Launch target program and start debugging session
    client.run()
```
