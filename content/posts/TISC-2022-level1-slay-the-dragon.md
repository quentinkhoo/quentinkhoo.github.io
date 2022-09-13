---
title: "TISC 2022 Level 1 - Slay The Dragon"
destription: "A pwn challenge during TISC 2022 that required exploiting the lack of server side validation"
date: 2022-09-12T00:01:00+08:00
draft: false
tags:
    - ctf
    - tisc-2022
    - python
    - pwn
categories:
    - ctf
    - writeup
    - tisc-2022
---

## Slay the Dragon Challenge Description
This was a pwn challenge and also the first challenge of the recent [TISC 2022](https://www.csit.gov.sg/events/tisc/tisc-2022) CTF organised by [CSIT](https://www.csit.gov.sg/). TISC 2022 was an individual CTF that is level-based and not exactly a typical jeopardy-style CTF, meaning that only 1 challenge is released at a time and only after you solve that 1 challenge do you unlock the next one. In this writeup, I will discuss my approach towards solving this particular pwn challenge.

```
DESCRIPTION
Topic: Pwn

The recently launched online RPG game "Slay The Dragon" has been hot topic in the online gaming community of late, due to a seemingly impossible final boss. Amongst the multiple tirades against the forementioned boss, much controversy has been brewing due to rumors of the game being a recruitment campaign for PALINDROME, the cybercriminal organisation responsible for recent cyberattacks on Singapore's critical infrastructure.

You are tasked to find a way to beat (hack) the game and provide us with the flag (a string in the format TISC{xxx}) that would be displayed after beating the final boss. Your success is critical to ensure the safety of Singapore's cyberspace, as it would allow us to send more undercover operatives to infiltrate PALINDROME.

To aid in your efforts, we have managed to obtain the source code of the game for you. We look forward to your success!

You will be provided with the following:

1. Source code for game client/server (Python 3.10.x)
2. Game client executable (Compiled with PyInstaller)
- Highly recommended that you run it in a modern terminal (not cmd.exe) for the optimal experience:
- Windows: Windows Terminal or ConEmu recommended.
- Linux: the default terminal should be fine.

Note: If you'd like to make any modifications to the client, we'd strongly suggest modifying the source code and running it directly. The game client executable has been provided purely for your convenience in checking out the game.

Host: chal00bq3ouweqtzva9xcobep6spl5m75fucey.ctf.sg
Port: 18261

ATTACHED FILES
slay_the_dragon.zip
```

## Introduction
Although the category was a `pwn` challenge, I would consider this more of a "source code review" challenge and spotting the vulnerability to be exploited. This was achieved by abusing the lack of proper server side validation from client side input. The provided source code can be found [here](https://github.com/quentinkhoo/quentinkhoo.github.io/raw/main/static/files/posts/tisc2022/slay_the_dragon.zip).

There were 3 bosses residing on the actual server, of which we had to defeat all 3 bosses in order to unlock the flag. We know this is the case by inspecting the `server/service/batttleservice.py` file, under the `__handle_battle_win(self)` function:

```python
def __handle_battle_win(self):
    self.server.game.remove_next_boss()
    if self.__boss_available_for_next_battle():
        self.server.send_result(Result.VALIDATED_OK)
        return
    self.server.send_result(Result.OBTAINED_FLAG)
    self.server.send_flag()
    self.server.exit()
```

We can only upgrade our sword once, from a measely 1 ATK point to 3 ATK points. We also have a starting HP of 10.

The first boss with an ATK of 1 and HP of 5 could be beaten easily, without resorting to any form of cheats/hacks/soure code modification.

The second boss however, had an ATK of 3 and HP of 30, and this led to the first exploit.

## Infinite Money Hack Without Dying
If we studied the client side's `workevent.py`, we see the following piece of code:

```python
CREEPER_ENCOUNTER_CHANCE = 0.2

class WorkEvent:
    def __init__(self, client: GameClient) -> None:
        self.client = client

    def run(self):
        if random() <= CREEPER_ENCOUNTER_CHANCE:
            self.__die_to_creeper()
        self.__mine_safely()

    def __die_to_creeper(self):
        screens.display_creeper_screen()
        screens.display_game_over_screen()
        self.client.exit()

    def __mine_safely(self):
        screens.display_working_screen()
        self.client.send_command(Command.WORK)
```
By removing the `if` statement and never having the chance of randomly running the `__die_to_creeper` function, we can effectively mine gold infinitely without having to worry about randomly dying!

This helped in defeating the second boss by consuming infinite potions during the course of the battle, but does not exactly help for the final boss as that one dealt a 1 hit K.O and I guess this is where the challenge really came in.

## Multi-Attack Hack

Let's first study and understand how the server side battle code works:

```python
# server/networking/client.py

@staticmethod
def send(data: str):
    sys.stdout.buffer.write(encode(data))
    sys.stdout.buffer.flush()

@staticmethod
def recv() -> str:
    return decode(NetClient.__recvuntil(EOF_MARKER))

@staticmethod
def __recvuntil(marker: str) -> bytes:
    data = b""
    while True:
        current_byte = sys.stdin.buffer.read(1)
        if current_byte == marker.encode():
            break
        data += current_byte
    return data
```
Going through `server/networking/client.py`, we can see that when data is received, it is received until the `EOF_MARKER`, which is just the `#` character as defined in  `core/config.py`.

```python
# Protocol
EOF_MARKER = "#"
```

On the other hand, `decode` and `encode` is simply done in base64 as shown in `core/networking/protocol.py`.

```python
from base64 import b64decode, b64encode

from core.config import EOF_MARKER

def encode(data: str) -> bytes:
    return b64encode(data.encode()) + EOF_MARKER.encode()

def decode(data: bytes) -> str:
    return b64decode(data).decode()
```

I guess the next thing to understand is the way the server processes a battle. Let's take a look at the `__compute_battle_outcome(self)` under `server/service/battleservice.py`:

```python
def __compute_battle_outcome(self) -> Optional[Result]:
    for command in self.history.commands:
        match command:
            case Command.ATTACK:
                self.boss.receive_attack_from(self.player)
                if self.boss.is_dead:
                    return Result.PLAYER_WIN_BATTLE
            case Command.HEAL:
                self.player.use_potion()
            case Command.BOSS_ATTACK:
                self.player.receive_attack_from(self.boss)
                if self.player.is_dead:
                    return Result.BOSS_WIN_BATTLE
```

Okay, from this we know that commands are iterated from `self.history.commands`. Let's take a look and see how this is populated. We can understand this from the `run(self)` function:

```python
def run(self):
    self.__send_next_boss()

    while True:
        self.history.log_commands_from_str(self.server.recv_command_str())

        match self.history.latest:
            case Command.ATTACK | Command.HEAL:
                self.history.log_command(Command.BOSS_ATTACK)
            case Command.VALIDATE:
                break
            case Command.RUN:
                return
            case _:
                self.server.exit(1)

    match self.__compute_battle_outcome():
        case Result.PLAYER_WIN_BATTLE:
            self.__handle_battle_win()
            return
        case Result.BOSS_WIN_BATTLE:
            self.server.exit()
        case _:
            self.server.exit(1)
```
Ahh, it seems like commands are stored in `self.history.commands` through the `log_commands_from_str(self, command_str: str)` function seen in `core/models/command.py`.

Let's take a deeper look at `log_commands_from_str()`:

```python
def log_commands_from_str(self, commands_str: str):
    
    self.log_commands(
        [Command(command_str) for command_str in commands_str.split()]
    )
```

Hmmm, what's interesting here is the use of `commands_str.split()`, which in python sense is splitting commands by the space delimeter.

At this an attack idea could be to send `ATTACK ATTACK ATTACK .... ATTACK ` for up to an indefinite number of times, which would result in the server processing multiple `ATTACK` commands. Let's trace how a single `ATTACK` happens:
1. Client sends an `ATTACK` command
2. Server receives `ATTACK` command
   - If the boss dies, the `PLAY_WIN_BATTLE` result is returned and the FLAG is sent.
3. Server runs `log_command` for `BOSS_ATTACK` command
   - We notice this in `run(self)` under `server/service/battleservice.py`
     - ```
        case Command.ATTACK | Command.HEAL:
            self.history.log_command(Command.BOSS_ATTACK)
4. Server sends a `BOSS_ATTACK` command
5. Client receives `BOSS_ATTACK` command

Hmmm, so it seems like for each `ATTACK` command, we have to send receive the `BOSS_ATTACK` as well. Well, the advantage to take of also comes from the fact that we can send multiple `ATTACK` commands first and it would calculate if the boss dies before the boss attacks. So, let's spam the boss with `ATTACK` before it even has the chance to strike back, like in a real game!

## The Hack - Source Code Modification
So my approach would be to introduce a `HACK` command into the gameclient that we can invoke:

Let's first modify the `core/models/command.py` file to include a `HACK` command:

```python
class Command(Enum):
    ATTACK = "ATTACK"
    BATTLE = "BATTLE"
    HACK = "HACK"
# ...
# ...
# ...
```
In the `client/gameclient.py`, we create a `hack_command(self, str)` function:

```python
def hack_command(self, str):
    self.__send(str)
```

Under our `client/event/battleevent.py` we create a new `__hack_boss(self)` function. This is also where we inject our payload:

```python
def __hack_boss(self):
    self.client.hack_command("ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ATTACK ")
    for i in range(120):
        self.boss.receive_attack_from(self.player)

```

I chose to ATTACK a 120 times only because my initial copy-pasta had 30 `ATTACK ` commands and I was just lazy :P

And finally, we create a way to invoke the `HACK` command by adding an additional option to through the switch/case statement in `client/event/battleevent.py`, which invokes the `__hack_boss()` function:

```python
case Command.HACK:
    self.__hack_boss()
    if self.boss.is_dead:
        break
```

To immerse in the experience fully, let's also update the `get_battle_menu()` function under `client/ui/menus.py` as well:

```python
def get_battle_menu() -> str:
    return (
        "   [red]1. [yellow]ATTACK\n"
        + "   [red]2. [yellow]HEAL\n"
        + "   [red]3. [yellow]RUN\n"
        + "   [red]4. [yellow]HACK"
    )
```

Alright let's run the `HACK` command against each boss and eventually, we will get the FLAG: 

```powershell
   █████    █████   █████   █████      █████  ██        ███   █████ ██   ██
   ██   █  ██   ██ ██      ██         ██      ██       █████   ███  ███  ██
   ██████  ██   ██  █████   █████      █████  ██      ██   ██  ███  ██ █ ██
   ██   ██ ██   ██      ██      ██         ██ ██      ███████  ███  ██  ███
   ██████   █████   █████   █████      █████  ███████ ██   ██ █████ ██   ██



                   Thank you for playing, here is your flag:

      TISC{L3T5_M33T_4G41N_1N_500_Y34R5_96eef57b46a6db572c08eef5f1924bc3}
```

