if [ ! -d .terraform ] ; then
  terraform init --backend-config="key=tor/dfpk/terraform.tfstate"
fi
