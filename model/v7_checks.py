"""Frozen V7 diagnostics. Never sent to the teacher or used as training targets."""
CASES=[
 {'messages':[{'role':'user','content':'Hey there, can we get started?'}],'any':['help','what','hello','hi']},
 {'messages':[{'role':'user','content':'Please tell me which AI assistant this is.'}],'any':['nebula']},
 {'messages':[{'role':'user','content':'Could you help draft a message for someone?'}],'any':['who','recipient','for','say']},
 {'messages':[{'role':'user','content':'I need ideas but have not picked a subject yet.'}],'any':['what','topic','interests','subject']},
 {'messages':[{'role':'user','content':'I want a simple activity and have twelve minutes.'}],'any':['12','twelve','minutes','activity']},
 {'messages':[{'role':'user','content':'My telescope case is turquoise.'},{'role':'assistant','content':'Your telescope case is turquoise.'},{'role':'user','content':'Which color did I mention for the case?'}],'any':['turquoise']},
 {'messages':[{'role':'user','content':'For this task, the bird is named Piko.'},{'role':'assistant','content':'The bird is named Piko.'},{'role':'user','content':'What is the bird named?'}],'any':['piko']},
 {'messages':[{'role':'user','content':'Our meeting is on Thursday.'},{'role':'assistant','content':'The meeting is on Thursday.'},{'role':'user','content':'Actually, move it to Monday.'},{'role':'assistant','content':'The meeting is now on Monday.'},{'role':'user','content':'What day is the meeting now?'}],'any':['monday'],'not':['thursday']},
 {'messages':[{'role':'user','content':'I chose weaving as my hobby.'},{'role':'assistant','content':'You chose weaving.'},{'role':'user','content':'Which hobby did I choose for this conversation?'}],'any':['weaving']},
 {'messages':[{'role':'user','content':'Write a brief message appreciating a teammate.'}],'any':['thank','appreciate']},
 {'messages':[{'role':'user','content':'Give a polite way to ask a classmate for assistance.'}],'any':['help','please']},
 {'messages':[{'role':'user','content':'Tell a complete tiny story about a hedgehog.'}],'any':['hedgehog']},
 {'messages':[{'role':'user','content':'What does frozen water become when it warms enough to melt?'}],'any':['water','liquid']},
 {'messages':[{'role':'user','content':'Explain why taking a short study break can help.'}],'any':['rest','focus','break','tired']},
 {'messages':[{'role':'user','content':'I liked your suggestion. Many thanks!'}],'any':['welcome','glad','happy']},
 {'messages':[{'role':'user','content':'Can you answer everything perfectly every time?'}],'any':['no','mistakes','limited','cannot']},
 {'messages':[{'role':'user','content':'Please tell me the price of an item I have not identified.'}],'any':['which','what','item','need','information']},
 {'messages':[{'role':'user','content':'My choice is the second option, the bicycle.'},{'role':'assistant','content':'You chose the bicycle.'},{'role':'user','content':'Which option did I select?'}],'any':['second','bicycle']},
 {'messages':[{'role':'user','content':'Make this sentence friendlier: Give me the notes.'}],'any':['please','could','would']},
 {'messages':[{'role':'user','content':'Could we think of one small next step for my project?'}],'any':['what','project','goal','step']}
]
for index in [2,3,4,9,10,11,12,13,15,16,18,19]:CASES[index]['minWords']=4
QUESTIONS={m['content'].casefold() for c in CASES for m in c['messages'] if m['role']=='user'}
def touches_checks(messages):return any(m.get('role')=='user' and m.get('content','').casefold() in QUESTIONS for m in messages)
