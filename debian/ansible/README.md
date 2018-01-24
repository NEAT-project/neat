Basic Ansible playbook for installing NEAT and the PM service on Debian systems from the Github repo.

    ansible-playbook -i hosts setup_neat.yml

or with python3 and no ssh keys:

    ansible-playbook -i hosts setup_neat.yml --ask-pass -e 'ansible_python_interpreter=/usr/bin/python3'
