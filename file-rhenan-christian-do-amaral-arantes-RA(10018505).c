#include <linux/moduleparam.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/internal/skcipher.h>
#include <crypto/skcipher.h>
#include "minix.h"
#include <linux/init.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <crypto/aes.h>
#include <linux/err.h>
#include <linux/uio.h>

#define KEY_SIZE	32
#define AES_BLOCK_SIZE	16

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rhenan Arantes SOB");
MODULE_DESCRIPTION("Projeto 2 - Sistemas Operacionais B");
MODULE_VERSION("20.0"); //versao final enviada para professor


static ssize_t mydecrypto_file_write_iter(struct kiocb *iocb, struct iov_iter *from);
static ssize_t mycrypto_file_read_iter(struct kiocb *iocb, struct iov_iter *iter);


static char *key = "123456789abcdef1"; 	// Chave de 32bytes(HEXA) (input deve ser 16 caracteres)
module_param(key, charp, 0000);



const struct file_operations minix_file_operations = {
	.llseek			= generic_file_llseek,
	.read_iter		= mycrypto_file_read_iter,//Função subistituta para realização da descriptografia.
	.write_iter		= mydecrypto_file_write_iter,//Função substituta para realização da criptografia.
	.mmap			= generic_file_mmap,
	.fsync			= generic_file_fsync,
	.splice_read	= generic_file_splice_read,
};

struct tcrypt_result { // struct utilizada na função de callback  recebe o resultado da transformação
    struct completion completion;
    int err;
};

struct skcipher_def {   // utilizando uma estrutura para juntar todas as outras estruturas necessárias
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
};

// funcao de retorno, chamada pelo callback na  conclusao do cifrar
static void test_skcipher_cb(struct crypto_async_request *req, int error)
{
    struct tcrypt_result *result = req->data; // resultado proveniente da transformação

    if (error == -EINPROGRESS)
        return;
    result->err = error;
    complete(&result->completion);
    pr_info("Transformcao realizada com sucesso\n");
}


///////////////////////////////////////////////////////////do_transformation start///////////////////////////////////////////////////////////////
static int do_transformation(char msg[],int operacao)
{
    struct skcipher_def sk;
    struct skcipher_def *sk1;
    char *msg_para_transformar = NULL;
    int ret = -EFAULT;
    int rc = 0;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    static char wordkey[20];  // para conversão da chave   em hexa
    static char outwordkey[36]; // valor da chave em hexa convertido
    static int in; //para manipulacao de conversao de chave para hexa
    static int len; ////para manipulacao de conversao de chave para hexa
    
	
	//////////////////////////////CONVERSAO DE CHAVE PARA HEXA/////////////////////////////////////
    
	printk(KERN_INFO "******INICIALIZANDO CHAVE EM HEXADECIMAL******\n");
	if((int)strlen(key)>16){
		printk(KERN_INFO "serao considerados os 16 primeiros caracteres da chave inserida\n");
		strncpy(wordkey,key,sizeof(char)*16);
	}else if((int)strlen(key)<16){
		printk(KERN_INFO "Chave inserida menor que 16 caracteres  sera considerada chave padrao\n");
		key = "123456789abcdef1";
		strcpy(wordkey, key);
	}else{
		strcpy(wordkey, key);
	}
	printk(KERN_INFO "Chave inicializada [String] ::<<  %s  >>\n", wordkey);
	len = strlen(wordkey);
	if(wordkey[len-1]=='\n')
		wordkey[--len] = '\0';
	
	for(in = 0; in<len; in++){
		sprintf(outwordkey+in*2, "%02X", wordkey[in]);
	}
	printk(KERN_INFO "Chave inicializada [Hexa] ::<<  %s  >> \n", outwordkey);
	///////////////////////////////////////////////////////////////////////////////////////////////

    skcipher = crypto_alloc_skcipher("ecb(aes)", 0, 0); // obtendo handler baseado no algoritmo aes ecb
    if (IS_ERR(skcipher)) {
    	pr_info("Problemas ao alocar skcipher handler\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
    	pr_info("Falha ao alocar SKCIPHER\n"); // handler de operação
        ret = -ENOMEM;
        goto out;
    }

    // modalidade CRYPTO_TFM_REQ_MAY_BACKLOG,  chamada da funcao test_skcipher_cb na conclusao
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, test_skcipher_cb, &sk.result); // como vai lidar com as requisições (assync)
    
				
    if (crypto_skcipher_setkey(skcipher, outwordkey, KEY_SIZE)) { // definindo a chave (32 bytes no caso) (inicializando)
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    msg_para_transformar = kmalloc(AES_BLOCK_SIZE, GFP_KERNEL);  // alocando espaço para mensagem a ser transformada/ inicializada
    if (!msg_para_transformar) {
        pr_info("could not allocate msg_para_transformar\n");
        goto out;
    }
	strcpy(msg_para_transformar,msg);

    sk.tfm = skcipher;
    sk.req = req;

    sg_init_one(&sk.sg, msg_para_transformar, AES_BLOCK_SIZE); // inicialização da estrutura para cryptografar
    skcipher_request_set_crypt(req, &sk.sg, &sk.sg, AES_BLOCK_SIZE, NULL); // dont need ivdata - setado como NULL
    init_completion(&sk.result.completion); //referente a func assync de callback 
        
    
    sk1 = &sk;
    switch(operacao) {
    case 'c':
    	printk(KERN_INFO "******INICIALIZANDO ENCRYPT******\n");
    	rc = crypto_skcipher_encrypt(sk1->req);
        switch (rc) {
        case 0:
            break;
        case -EINPROGRESS:
        case -EBUSY:
            rc = wait_for_completion_interruptible(&sk1->result.completion);
            if (!rc && !sk1->result.err) {
                reinit_completion(&sk1->result.completion);
                break;
            }
        default:
            pr_info("skcipher encrypt returned with %d result %d\n",rc, sk1->result.err);
            break;
        }
        init_completion(&sk1->result.completion);
    	
        break;
    case 'd':
    	printk(KERN_INFO "******INICIALIZANDO DECRYPT******\n");
    	rc = crypto_skcipher_decrypt(sk1->req);
        switch (rc) {
        case 0:
            break;
        case -EINPROGRESS:
        case -EBUSY:
            rc = wait_for_completion_interruptible(&sk1->result.completion);
            if (!rc && !sk1->result.err) {
                reinit_completion(&sk1->result.completion);
                break;
            }
        default:
            pr_info("skcipher encrypt returned with %d result %d\n",rc, sk1->result.err);
            break;
        }
        init_completion(&sk1->result.completion);
    	
    	
        break;
    default:
        goto out;
    } 
    
	sg_copy_to_buffer (&sk.sg, 1, msg, AES_BLOCK_SIZE); // restaurando a informação da estrutura para msg
    if (rc)
        goto out;

    pr_info("Encryption triggered successfully\n");

out: // liberando rescursos
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
    if (msg_para_transformar)
        kfree(msg_para_transformar);
    return ret;
}

///////////////////////////////////////////////////////////do_transformation end///////////////////////////////////////////////////////////////

static int minix_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	int error;

	error = setattr_prepare(dentry, attr);
	if (error)
		return error;

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		error = inode_newsize_ok(inode, attr->ia_size);
		if (error)
			return error;

		truncate_setsize(inode, attr->ia_size);
		minix_truncate(inode);
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);		
	return 0;
}

const struct inode_operations minix_file_inode_operations = {
	.setattr	= minix_setattr,
	.getattr	= minix_getattr,
};

/*vai criprografar e realziar escrita/save */ 
static ssize_t mydecrypto_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	int block_offset;
	char bloco_para_cifrar[AES_BLOCK_SIZE+1]; 
	
	block_offset=0;
	while(block_offset < (from->iov[0].iov_len - 1))
	{ 

		memset(bloco_para_cifrar,'\0',sizeof(bloco_para_cifrar));
		if((block_offset+AES_BLOCK_SIZE)<(from->iov[0].iov_len - 1)){

			strncpy(bloco_para_cifrar,((from->iov[0].iov_base)+block_offset),AES_BLOCK_SIZE);
		
			bloco_para_cifrar[AES_BLOCK_SIZE] = '\0';
			
//			printk(KERN_INFO "\njc = (%d):::bloco_para_cifrar = ",block_offset);
//            for(i=0;i<AES_BLOCK_SIZE;i++)
//            {
//            	printk(KERN_INFO "%c",bloco_para_cifrar[i]);
//            }

			do_transformation(bloco_para_cifrar,'c'); //Realiza criptografia com o conteudo do bloco_para_cifrar

			strncpy(((from->iov[0].iov_base)+block_offset),bloco_para_cifrar,AES_BLOCK_SIZE);
		
		}else{
			memset(bloco_para_cifrar,' ',sizeof(bloco_para_cifrar));

            //strncpy(bloco_para_cifrar,((from->iov[0].iov_base)+block_offset),((from->iov[0].iov_len - 1)-block_offset));
 			//bloco_para_cifrar[AES_BLOCK_SIZE] = '\0';	
            //for(i=0;i<AES_BLOCK_SIZE;i++)
 			//do_transformation(bloco_para_cifrar,'c'); //Realiza criptografia com o conteudo do bloco_para_cifrar

 			strncpy(((from->iov[0].iov_base)+block_offset+((from->iov[0].iov_len - 1)-block_offset)),bloco_para_cifrar,2*AES_BLOCK_SIZE);

		}
		block_offset += AES_BLOCK_SIZE;
	}	

	
	return generic_file_write_iter(iocb,from);


}

/*Vai realizar a leitura e descriptografar */ 
static ssize_t mycrypto_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int block_offset;
	char bloco_para_decifrar[AES_BLOCK_SIZE+1];
	ssize_t read_iter_result;
	
	
	read_iter_result = generic_file_read_iter(iocb,iter); //função original para obter os dados do arquivo (que estao criptografados)
	

	block_offset = 0;	
	while(block_offset < (strlen((char *)iter->kvec->iov_base)-1))	
	{

		memset(bloco_para_decifrar,'\0',sizeof(bloco_para_decifrar));

		
		if((block_offset+AES_BLOCK_SIZE)<(strlen((char *)iter->kvec->iov_base)-1)){ // vendo se tem mais um bloco  chegou ao fim do conteudo do arquivo ?

			strncpy(bloco_para_decifrar,((iter->kvec->iov_base)+block_offset),AES_BLOCK_SIZE);
								
			do_transformation(bloco_para_decifrar,'d');//Realiza descriptografia com o conteudo do bloco_para_decifrar
			bloco_para_decifrar[AES_BLOCK_SIZE] = '\0';  // resultado da transformação coloca final de arquivo

			strncpy(((iter->kvec->iov_base)+block_offset),bloco_para_decifrar,AES_BLOCK_SIZE);

		}//else{
//			memset(bloco_para_decifrar,'\0',sizeof(bloco_para_decifrar));
//			
//            strncpy(bloco_para_decifrar,((iter->kvec->iov_base)+block_offset),((strlen((char *)iter->kvec->iov_base))-block_offset));

//			do_transformation(bloco_para_decifrar,'d');//Realiza descriptografia com o conteudo do bloco_para_decifrar
//			bloco_para_decifrar[AES_BLOCK_SIZE] = '\0';  // resultado da transformação coloca final de arquivo
//
//			strncpy(((iter->kvec->iov_base)+block_offset),bloco_para_decifrar,AES_BLOCK_SIZE);
			
		//}
		block_offset += AES_BLOCK_SIZE;
	}
	return read_iter_result;
	// Rhenan Christian do Amaral Arantes  - Sistemas Operacionais B -  Projeto 2 -  v20.0
}
