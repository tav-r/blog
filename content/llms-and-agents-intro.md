+++
title = "LLMs and Agents: Intro"
date = 2026-09-04
description = "This is the first article in a short series about what people today like to call 'AI agents'. The concept is first discussed on an abstract level. The second part will be more technical and I will step through the details of how a Large Language Model can be used to 'carry out actions.' The goal is to give a realistic idea of what 'AI agents' technically are and to lay the foundations to get started with building tools."
+++
 
## Claims
 
- The vocabulary used to describe LLMs and their application is misleading at best. Our [action theoretic](https://plato.stanford.edu/entries/action/) intuitions may sometimes carry over to the technical domain, but at a certain point they become a problem.
- People often make 'LLM agents' seem almost sci-fi. In reality, turning an LLM into an 'agent' is almost disappointingly simple.
- 'AI Agents' can only do what we let them do. What gets executed and what the LLM learns about the outcome is entirely up to the programmer.
- The problem we face is recklessness, not 'AI going rogue'.

## Remarks Upfront
This post is half technical, half opinion piece. If you already have some technical experience with LLM tooling and how things like MCP work, you might not learn much new stuff.


## Sci-Fi and Large Language Models
> The laser flickered on a failure sensor, a sensor that reported critical changes in one of the ultradrive spines. Its interrupts could not be ignored if the star jump were to succeed. Interrupt honored. Interrupt handler running, looking out, receiving more light from the laser far below.... a backdoor into the ship's code, installed when the newborn had subverted the humans' groundside equipment....
>
> .... and the Power was aboard, with milliseconds to spare. Its agents &mdash; not even human equivalent on this primitive hardware &mdash; raced through the ship's automation, shutting down, aborting. There would be no jump. Cameras in the ship's bridge showed widening of eyes, the beginning of a scream. The humans knew, to the extent that horror can live in a fraction of a second
&mdash; [Vernor Vinge - *A Fire Upon the Deep*](https://en.wikipedia.org/wiki/A_Fire_Upon_the_Deep)

Pop culture is full of depictions of 'AI going rogue'. The quotation above is from a book published in 1992 but the concept is at least a decade older (think of Skynet). [Since the beginning of the current 'AI' boom] companies have been invoking the idea of an artificial superintelligence becoming a danger to humanity and [lately](https://www.bbc.com/news/articles/c14dpgm0rg4o) some tech CEOs brought up the topic again.
 
While there are [non-fiction writings about this topic](https://en.wikipedia.org/wiki/Superintelligence:_Paths,_Dangers,_Strategies), I think it is uncontroversial to say that fiction shapes our conception of technology. We do not refer to Large Language Models (LLMs) as statistical autocompletion software, we refer to this technology as 'Artificial Intelligence'. And to a large extent, technology is also developed to fit our expectations. LLMs have various applications, ranging from [sentiment analysis](https://aclanthology.org/2024.findings-naacl.246/) through translation to powerful code completion. From a consumer perspective, however, the ultimate breakthrough of LLMs came in the form of a web chat that feels like chatting with a human. OpenAI had implemented the [imitation game](https://en.wikipedia.org/wiki/Turing_test).
 
It is not a secret how these LLMs work and anyone who is willing to [do the reading](https://www.manning.com/books/build-a-large-language-model-from-scratch?utm_source=raschka&utm_medium=affiliate&utm_campaign=book_raschka_build_12_12_23&a_aid=raschka&a_bid=4c2437a0&chan=mm_website) or to watch [some videos on YouTube](https://www.youtube.com/watch?v=aircAruvnKk&list=PLZHQObOWTQDNU6R1_67000Dx_ZCJB-3pi) can understand the technology very well. The truth is that what we call 'AI' today is applied statistics. [Transformers](https://en.wikipedia.org/wiki/Transformer_(deep_learning)) split machine input into tokens and &mdash; if they are sufficiently well trained &mdash; emit tokens that are likely to extend the input to something that resembles a certain data set, whether that data set is a huge text corpus or [generated ad-hoc in a dialogue setting](https://en.wikipedia.org/wiki/Reinforcement_learning_from_human_feedback). That's it, really. And since [the initial breakthrough](https://arxiv.org/abs/1706.03762) there has been no fundamental architectural change. New ways of generating high-quality training data were found (Reinforcement Learning from Human Feedback, RLHF) and models became cheaper to run (Mixture of Experts, MoE). The rest was size: more data, larger models, more memory for GPUs/TPUs. Do we really need to ask whether LLMs think? Whether they are conscious? In my opinion: only if you have a very weird idea of what 'thinking' or 'consciousness' means. But LLMs generate sequences of tokens that read like human-written text, which is why we like to think of them as being 'intelligent'; this psychological phenomenon even has a name, it's the [ELIZA effect](https://en.wikipedia.org/wiki/ELIZA_effect).
 
Personally, I don't like using anthropomorphizing vocabulary to describe what LLMs produce but I use it anyway (and I will do so throughout this post). It is just easier to say 'Claude said X' than to say 'One of the large language models hosted by Anthropic emitted a sequence of tokens which reads like human-made text that can be read as expressing X'. The products companies like OpenAI and Anthropic try to sell us are *intentionally designed* so that we can interact with them as if they were sentient, rational, speaking beings. Even if they actually cannot really answer a question (they auto-complete something that looks like a dialogue), we are used to saying that we 'ask' them. Even though they cannot justify their statements (they are not the kind of thing that is responsible for claiming or doing something), we are told that they 'reason' before they give an answer.
 
Because yes, this vocabulary works surprisingly well. Where I think anthropomorphization becomes a real problem is when it comes to 'AI agents' (I will use the terms 'AI agent', 'LLM agent' and sometimes just 'agent' interchangeably). Let me illustrate this point.
 
## The OpenAI-Hugging Face Incident and Conceptual Confusion
 
On July 16, [Hugging Face (HF) disclosed](https://huggingface.co/blog/security-incident-july-2026) that they got breached 'earlier this week' and called it an 'AI-driven intrusion'. [Four (!!) days later OpenAI noticed that it was them](https://openai.com/index/hugging-face-incident-and-the-road-ahead/). A 'swarm' of 'autonomous agents' that was supposed to not have internet access found a way to run arbitrary code on some of HF's servers. These agents were deployed to perform 'internal cybersecurity evaluations' and had been running for more than two months at this point. OpenAI somehow managed to turn this into a PR stunt. They [went to Black Hat USA](https://www.youtube.com/watch?v=87DyyMV0kCY) to give an overview of the events and from then on most security folks [zeroed in on the technical details](https://www.youtube.com/watch?v=V4zb8QhQY58).
 
Using anthropomorphizing vocabulary to describe this event makes the incident sound like a sci-fi story, a bit like 'the Blight' breaking out in the cited paragraph above from Vinge's novel. I think this is misleading in at least two different ways:

1. It leads to a misattribution of responsibilities.
2. It gives a very wrong impression of what is going on on a technical level.

It should be obvious that an LLM cannot be responsible for 'doing' something. Blaming a statistical model of a text corpus simply doesn't make any sense. There is some [philosophical discussion around whether machine learning technologies introduce responsibility gaps](https://link.springer.com/article/10.1007/s10676-004-3422-1), i.e., whether in some situations in which opaque algorithms influenced the outcome of a certain process, responsibility for negative outcomes somehow disappears. There are indeed interesting discussions to be had around this, especially when it comes to medical applications. However, the OpenAI-Hugging Face incident is absolutely free from responsibility gaps. OpenAI [says](https://openai.com/index/hugging-face-incident-and-the-road-ahead/) they were running 'internal-only research model\[s\] comparable in scale to GPT‑5.6 Sol' that were 'operating under reduced safeguards' after [announcing two months earlier](https://openai.com/index/previewing-gpt-5-6-sol/) that their new model (5.6 Sol) had '\[s\]tronger cyber capabilities'.

I use LLM agents pretty often in a professional context. This setting definitely sounds to me like one where something could go wrong. Given the risk level, however, OpenAI's security posture seems surprisingly weak. Sandboxing (jargon for isolating agents from a certain environment) is one point, proper monitoring of what their 'agents' are doing a second, even more important one. It took more than a week for OpenAI to figure out that their internal testing had resulted in a successful attack against HF. Given how transparent the actions of an LLM agent are on a technical level (more on that later), this lack of monitoring does not seem to square well with [the company's charter](https://openai.com/charter/), where they express concern 'about late-stage AGI development becoming a competitive race without time for adequate safety precautions'.
 
The bottom line is this: The wording around this incident is full of anthropomorphization: the agents were 'planning', models 'debated and pushed back' and eventually 'breached' HF. All this sounds like OpenAI was trying to tame some kind of dangerous cyber god with an intent to hack and sadly failed. In fact, they knowingly let their servers run potentially damaging programs with unpredictable outcomes without sufficient supervision. Neither are LLMs to blame nor do they introduce a responsibility gap here.
 
But how do LLMs *do* this kind of stuff? ChatGPT can certainly not break out of your browser and hack your computer. Or can it?
 
## Automating Copy-Paste, aka. 'Human Out of the Loop'
You might have been in a situation where you ran into computer issues and started engaging in a kind of *back-and-forth loop* with an LLM chatbot. You explain your problem, the chatbot tells you to try X. Maybe it tells you to click something, to install some software, to paste something into the command line interface. You try X and report back the outcome to the chatbot. It tells you to do Y next, you do so and report back again. If you do this long enough, you might get lucky and eventually solve your problem. An 'AI agent' is exactly that, just with you removed from the loop.
 
To make an LLM agent work, three things are required:
- The LLM must be able to say that it wants to run something. That is, the LLM must somehow be able to indicate that it 'wants' a certain program or tool to be run. There must be a way to determine if a certain part of the LLM output is supposed to be just prose (an 'answer') or a description of a procedure to run (for example, a mouse click, a web request or a command to be executed). Modern LLMs are trained to emit special tokens to mark parts of their output as a tool call.
- The LLM needs to 'know' what it *can* run. More precisely, a prompt has to be sent to the LLM which contains an explanation of what options are available. Intuitively, the LLM must 'know' *which tools* (click, web request, command execution) it has access to and *how these tools are used*, i.e., how a specific application of the tool has to be described. There are standards for this kind of tool description, the most prominent one being the Model Context Protocol (MCP). Again, modern LLMs are fine-tuned to interpret tool descriptions reliably.
- LLM output has to be routed appropriately. A piece of software, commonly called a 'harness', reads and interprets the output of the LLM. For each (valid) description of a tool call in its output, the harness executes the respective procedure.
The last point is what makes it possible to remove human users from the back-and-forth loop. Instead of 'telling' you to paste something to the command line, the LLM issues a description of a command that should be executed and the harness executes the command. For this to work, the first two points are important: they define the *protocol*. Unlike humans, computers are not very flexible at understanding instructions. The protocol describes the exact format of the back-and-forth between computer and LLM, so that the harness can deterministically parse and interpret the output of the LLM.
 
> **LLM Harness**: *A piece of software that a) sends user prompts (which may describe tasks) and procedure output to an LLM and b) runs procedures based on LLM output.*
 
Let's look at a concrete example. An MCP definition of a tool that can be used to play a beep could look like this:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {
        "name": "make_beep",
        "title": "Make Beep",
        "description": "Play an audible beep on the host speaker.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "duration_ms": {
              "type": "integer",
              "description": "Beep length in milliseconds.",
              "minimum": 10,
              "maximum": 5000,
              "default": 200
            }
          },
          "required": [],
          "additionalProperties": false
        }
      }
    ]
  }
}
```
 
The standard makes use of a simple notation called JSON that can be used to represent different kinds of structured data. As you can see, an MCP tool definition contains a tool name, a description, certain ways in which the tool can be used and some other stuff. The definition (in a slightly shorter form) is then sent to the LLM along with a prompt like 'Please beep for me!' (technically, it is usually sent before the prompt but that's not important here). An LLM that was trained to understand MCP might then respond with the following text:
```
<thinking>
User wants a beep. Only knob is length; a short one is fine.
</thinking>
 
Beeping.
 
<tool_call id="toolu_2342blabla" name="make_beep">
{"duration_ms": 150}
</tool_call>
```
 
So the answer names the tool and also specifies a parameter (the duration of the beep sound). Of course, this doesn't beep yet. This response has to be processed by some piece of software, often called a *harness*. The harness is what replaces you in the back-and-forth loop. It parses the response from the LLM and potentially triggers some other event on the computer. A proper harness dealing with this tool would parse the response and look for occurrences of `<tool_call name="make_beep">...</tool_call>` and then trigger a beep of the requested length. After the beep is executed, the harness has to report back to the LLM to 'inform' it about the outcome of the tool call. This means that it sends the LLM something like:
 
```
<tool_result name="make_beep" id="toolu_2342blabla">
Beeped for 150 ms.
</tool_result>
```
 
You know LLMs, they always answer, so this will trigger one final answer from the model, something like this:
```
<thinking>
Beep played, nothing else to do.
</thinking>
 
Done - that's your beep.
```
 
This is what happens behind the scenes. The user of this beeping agent will observe something like this:
>*User*:  Please beep for me!
>
>\**User hears short beep*\*
>
>*Agent*: Done &mdash; that's your beep.
 
 
This is nothing fundamentally new. The protocol defines a way in which the computer and the LLM can interact. LLMs get trained to be good at understanding tool definitions and emitting syntactically correct tool calls. The harness is a piece of software that parses LLM responses and deterministically executes the functionality the LLM requests.
 
What does it take to go from our beeping AI agent to a member of a swarm of hacker agents pwning Hugging Face? Well, just different tools. It turns out that 'smarter' models can operate the command line pretty well, so for some complex tasks the simplest way for an LLM agent to approach them might be to directly execute commands on the computer. A naive definition could look like this:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {
        "name": "run_bash",
        "title": "Run Bash Command",
        "description": "Run a shell command and return its output.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "command": {
              "type": "string",
              "description": "The command to run."
            }
          },
          "required": ["command"],
          "additionalProperties": false
        },
        "annotations": {
          "readOnlyHint": false,
          "destructiveHint": true,
          "idempotentHint": false,
          "openWorldHint": true
        }
      }
    ]
  }
}
```
 
So if the user asks how much space the current directory on their Linux system occupies, the LLM might generate something like:
```
<thinking>
User wants the size of the current directory. `du -sh .` is the one-liner.
</thinking>
 
Checking the directory size.
 
<tool_call id="toolu_1337abc" name="run_bash">
{"command": "du -sh ."}
</tool_call>
```
 
The harness executes it and sends the output of the command to the LLM:
```
<tool_result tool_use_id="toolu_1337abc">
exit_code: 0
stdout:
1.4G	.
stderr:
</tool_result>
```
 
and the LLM can then provide an answer:
```
<thinking>
Exit code 0, output is "1.4G\t." — the current directory is 1.4 GB. Nothing
else to run.
</thinking>
 
The current directory is 1.4G.
```
 
If you give your agent a command execution tool, it will most likely not use any other tools. We can safely assume that the agents that hacked Hugging Face almost exclusively used the command line; at least this is what all popular LLMs in off-the-shelf harnesses tend to do nowadays.
 
## Chatbots Talking to the Computer
So this is what 'AI agents' are made of: LLMs that issue commands, computer programs that execute these commands and report the observed outcome back to the LLM. I think it is fair to describe them as 'chatbots talking to the computer'. The impressive part is, of course, that LLMs can carry out quite complex tasks when you do this in a loop. Keeping all of this in mind, what does this tell us about the HF hack?
 
One important point is this: what an LLM agent is doing is in principle 100% traceable. It is true that there is an interpretability problem with LLMs. But as soon as an LLM's output is used to execute commands on a computer, every single command can land in a log file. At the scale at which OpenAI ran their experiment, it was of course impossible to have full human supervision. But since OpenAI is an AI company, I'm sure they would in principle be capable of coming up with a way to monitor a log for certain patterns. If not, the reasonable response would be to perform the experiment on a smaller scale. Whatever, it seems like everything turned out well for them, right?
 
Furthermore, it is clear that 'AI agents' can only do what the tools allow them to do. If you don't (automatically) issue commands based on LLM output, an LLM will never run a command on your computer. This, as well as what the LLM learns about the outcome of a certain procedure, is 100% up to the harness.

Taken together, this should reframe events in which LLMs cause damage. We know that LLMs are said to 'hallucinate'. Furthermore, the correct, risk-minimal and ethically acceptable way to execute a given task might not be in the training data, might not get learned properly by the model or might get lost during post-training, when the model is optimized for something else. LLMs not behaving as we expect is a statistical artifact.
 
I think getting all of this straight shows that events like the OpenAI-Hugging Face incident are not so much a matter of 'AI going rogue' but of an 'AI' company being rather reckless.

## Conclusion
To summarize all of this: LLM agents are a way to use text generators for computer automation. People like to think and talk about them as some kind of intelligent beings, living in computers, planning and executing tasks &mdash; an idea mostly taken from fiction. In reality, they function as a feedback loop: prompt -> token prediction -> command execution -> output as prompt -> token prediction -> ...
 
I should make clear that I definitely think LLM agents can be both useful and potentially dangerous. However, the danger they pose is less that of an intelligent adversary that pursues its own goals. It is the kind of danger that comes from using a technology that is known to produce mixed and unexpected results for stuff that can have quite an impact.
 
