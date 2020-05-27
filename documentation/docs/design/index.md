Some Background
===============

The following topics cover some concepts (at a high level) that should
be first understood if you're curious about where ACE comes from or the
bigger picture of how ACE is meant to be used.

I gave a talk on the development of the tool at BSides Cincinnati in
2015 which covers these topics in detail. You can watch his presentation
here:

<iframe width="560" height="315" src="https://www.youtube.com/embed/okMkF-NYCHk?rel=0" frameborder="0" allow="autoplay; encrypted-media" allowfullscreen></iframe>

Driving Behavior
----------------

The metric this tool attempts to drive is called **time to
disposition**, or, *how long does it take to figure out you're wasting
your time?* Most people would phrase this as *how long does it take to
work an alert?* but I've taken a different approach to how we look at
alerts.

Generally, analysts tend to open up whatever alert they're looking at
and try to figure out if it's "bad" or not. And by "bad", they usually
mean "Is this an attack?", or, "Is this something I need to worry
about?"

Over the years as an analyst, I came to realize that most of the alerts
I worked ended up being dispositioned as false positive, with the
following definition of what a false postive actually is.

False Positive - An alert you're not going to respond to.
----------------

I think many people define a false positive more in terms of mismatching
something, such as a network-based packet alert that pattern matched
something, but that pattern matched something it wasn't intended to
match. This is obvious. But I would expand that definition even further.
For example, suppose you get an alert from your IDS that a remote MySQL
exploit was attempted against a server you protect, but that server does
not run MySQL. How would you disposition the alert? It was an attack for
sure, but it doesn't matter if the target of the attack is not running
the software the attack is meant to exploit. It would matter even less
if you didn't run MySQL at all. (Note that I would consider the
intelligence gained from the attack as another matter entirely and not
the focus of this topic.)

So when I applied that definition of what a false positive is, I found
that almost **all** of the alerts I worked ended up being false
positive. In my presentation at the Cincinnati b-sides, I even stated
that **99% of alerts are false positive**.

For the sake of argument here, we assume this is the case. This changes
how alerts are analyzed. If 99% of them are false positive, then what is
the chance that what is being analyzed is something to worry about? So
rather than answer the question *"Is this bad?"* we answer the question
*"Am I wasting my time?"* because 99% of the time that's exactly what is
happening!

This idea gets some resistance. I've seen many security organizations
take the approach of always attempting to minimize the number of false
positives their tools are generating, (rightfully) thinking their
analysts waste their time working them, and thus the **only** alerts
that *should* be generated are the true positive alerts that are
accurately identifying an attack.

I disagree with that and here is why.

Algorithms and Metrics 
----------------

An analyst can work a certain number of alerts in a given day. How large
that number is depends on a number of factors such as

-   how skilled they are.
-   how good their tools are.
-   how focused they are.
-   how much analysis paralysis has set in (aka alert burn-out.)

Say we measure the number of alerts the analysts can work in a given day
as measurement **W**.

Now, there are a number of tools deployed that are generating alerts.
Say we measure the number of alerts generated in a given day as
measurement **N**. All of the signatures, rules, engines and algorithms
they use to generate these alerts gives the network being protected
**coverage**. We define **coverage** as "this is all the places and
things we're constantly monitoring for evidence of a compromise or
attack." Say we measure this coverage as measurement **C**.

So now we have tools generating **N** alerts giving us a coverage of
**C**, with the analysts able to work **W** of the **N** alerts.

The metric to drive here is **C**. The higher the value of **C**, the
more difficult it is for an attacker to have a successful attack
*without being detected.* The issue is that an increase in **C** usually
results in an increase in **N**, but **W** stays the same.

The goal is to *always* be increasing **C** while keeping **N** less
than or equal to **W**. In English that would read as "always increasing
coverage while keeping the number of alerts manageable."

This is accomplished by a continuous process of hunting, automation and
tuning.

Hunting is how **C** increases. You look somewhere you were not looking
before. This can be literally anything that makes sense: a new snort
rule, a new saved search in splunk, a new script that runs that checks
some weird system you have. Anything that would generate new **alerts**
to be analyzed by the analysts.

Automation is how the increase to **C** is actually made permanent. This
means running the hunt continuously, forever or until it doesn't make
sense any more. For some tools this is natural, for example, a snort
rule always runs after it's deployed. But you may need to build
something to run that splunk search every so often, or to run that
script on a cron job as certain times.

Finally, tuning is how to manage the increase in **N**. This is the
action of **preventing the tools from generating false positive
alerts.** This is accomplished in one of two ways:

-   modifying the hunt to avoid the false positives. For example,
    tweaking the signature to be more specific in the match, or adding
    additional boolean logic clauses to queries (such as NOT this AND
    NOT that AND NOT that.)
-   turning off the alert entirely in the case where the hunt is either
    wrong or not tunable.

At this point, we're constantly increasing **C** by following the
process of hunting, automating and tuning, keeping the number of alerts
**N** manageable to a team of analysts that can handle **W** alerts in a
given day.

So where does ACE come into play here? It drives the one metric not
covered yet: **W**.

*ACE increases the number of alerts an analyst can work in a given day.*

The higher the value of **W** is, the more aggressive a team can get
with **C**. Teams with a low value of **W** are easily overwhelmed by
very small increases to **C**. Teams with a high value of **W** can
handle large increases to **C**.

If viewed on a chart over time, the value of **N** should look more like
a sine wave, fluctuating as new hunts are automated and tuning is
performed on the old hunts. The value of **C** should always be rising,
even if only gradually.

Finally, it's worth noting that in this scenario I'm describing the
number of false positive alerts is very close to **N**, because 99% of
all alerts are false positive (assuming our definition.) Thus, the
effort to reduce false positive alerts is merely a function of the
process, and not a goal in itself.
