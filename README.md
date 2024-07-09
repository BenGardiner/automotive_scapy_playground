# Automotive-scapy 🚗 Playground 🎢

A place for simple tasks with automotive scapy.

Automotive scapy and python-can are really great! Many kudos to the authors of these great packages. Thanks to them we can interact with vehicle networks in a platform independent way.

We hope you find this repo useful as a starting point for learning how to use these packages. For more advanced applications, use those packages directly.

## The Jupyter Notebooks

For a few 'easy'[^1] tasks:
1. logging some CAN traffic: [`easy_log.ipynb`](easy_log.ipynb)
2. sending CAN messages and logging: [`easy_send.ipynb`](easy_send.ipynb)
3. sending and receive a ISO-TP message and response: [`easy_isotp_send.ipynb`](easy_isotp_send.ipynb)

[^1]: 'easy' is very subjective and these tasks will seem much _easier_ once you have done them a few times. Hopefully these notebooks make the first, second and third time _easy_.

How to use:
1. clone this
2. cd to the cloned directory
1. install all the python dependencies `python -m pip install -r requirements.txt`
2. launch jupyter-notebook (this should open a browser automatically) `python -m jupyter notebook` (or try `python -m notebook` if that doesn't work)

## The Example Script

For more complex tasks there is an example script in [`example.py`](example.py) where scapy is setup along with a couple CAN logging options (both candump style and wireshark).
