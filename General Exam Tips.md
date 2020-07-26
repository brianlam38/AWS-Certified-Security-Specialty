# General Exam Tips

Multiple choice:
* Read question carefully and highlight key points.
* Don't spend too long thinking about a question - skip and go back to it later.
* If you have spare time at the end, re-read each question carefully to check if your answer made sense.
* There are usually _two blatantly incorrect_ answers, and _two answers that could be right_. Narrow down your choices.

AWS Specific
* Lots of questions on _stopping lateral movement across EC2s_
    * Most of the time you need to stop the instance and take a snapshot for forensic purposes.
    * You also need to make sure that security groups in an Auto-Scaling Group do not allow for transmission between instances on the same tier.
* Understand cross-account access to various resources.
* Understand "_blast-radius_" of compromised AWS keys (KMS).
* CloudWatch or any AWS service cannot monitor your EC2 instances _unless an Agent has been installed_.