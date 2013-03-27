mipass - a password keeping service
***********************************

password encryption
===================

.. autofunction:: mipass.mi_encrypt

.. autofunction:: mipass.mi_decrypt

pass_db
=======
.. autoclass:: mipass.pass_db
   :members: get_pass, set_pass, set_master, check_master, state

socket server
=============
.. autoclass :: mipass.master_handler
   :members:

socket client
=============
.. autoclass :: mipass.client
   :members:

Inner methods
=============
.. autoclass:: mipass.pass_db
   :members: get_master_hash
   
.. autofunction:: mipass.url_hash
