#include<string.h>
#include<openssl/bn.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<time.h>

#ifdef DEBUG
#define dbg(...) printf(__VA_ARGS__)
#else
#define dbg(...)
#endif

#define FLAGFILE "/flag"

// actual bit is 4 * length
#define SMALL_PRIME_HEX_LEN 128
#define PREFIX_HEX_LEN 120

static BIGNUM *BN_0 = NULL;
static BIGNUM *BN_1 = NULL;
static BIGNUM *BN_3 = NULL;
static BIGNUM *BN_5 = NULL;
static BIGNUM *BN_7 = NULL;

static BN_CTX *ctx = NULL;

char prefix_hex[PREFIX_HEX_LEN + 4];

void set_bn_constant(BIGNUM **bn, unsigned long w){
  *bn = BN_new();
  BN_set_word(*bn, w);
}

void init(){
  set_bn_constant(&BN_0, 0);
  set_bn_constant(&BN_1, 1);
  set_bn_constant(&BN_3, 3);
  set_bn_constant(&BN_5, 5);
  set_bn_constant(&BN_7, 7);

  ctx = BN_CTX_new();
  
  memset(prefix_hex, 0, sizeof(prefix_hex));
}

void clean(){
  BN_free(BN_0);
  BN_free(BN_1);
  BN_free(BN_3);
  BN_free(BN_5);
  BN_free(BN_7);
}

int satisfy_prime_condition(BIGNUM *p, BIGNUM *a, BIGNUM *k, BIGNUM *ks, BIGNUM *p_minus){
  BIGNUM *temp = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  BN_mod_exp(temp, BN_3, ks, p, ctx);
  if (BN_cmp(temp, p_minus)) return 0;
  // gcd(a ^ k mod p + 1, p) == 1
  BN_clear(temp);
  BN_mod_exp(temp, a, k, p, ctx);
  BN_add(temp, temp, BN_1);
  BN_gcd(temp, temp, p, ctx);
  if (BN_cmp(temp, BN_1)) return 0;
  return 1;
}

BIGNUM *generate_prime(BIGNUM *s, BIGNUM *not_equal){
  dbg("generating prime\n");
  // generated prime cannot be not_equal
  BIGNUM *p = BN_new();
  BIGNUM *k = BN_new();
  BIGNUM *p_minus = BN_new();
  BIGNUM *ks = BN_new();
  dbg("  Pocklington\n");
  // Pocklington
  BIGNUM *top = BN_new();
  BN_add(top, s, BN_1);
  int iteration = 0;
  while(1){
    // randomize k
    BN_rand_range(k, top);
    if (!BN_cmp(k, BN_0)) continue;
    // ks = k * s
    // p = 2 * k * s + 1
    // p_minus = 2 * k * s 
    BN_mul(ks, s, k, ctx);
    BN_lshift1(p_minus, ks);
    BN_add(p, p_minus, BN_1);
    if (not_equal != NULL && !BN_cmp(p, not_equal)) continue;
    if (satisfy_prime_condition(p, BN_3, k, ks, p_minus) 
        || satisfy_prime_condition(p, BN_5, k, ks, p_minus) 
        || satisfy_prime_condition(p, BN_7, k, ks, p_minus))
      break;
    iteration++;
  }
  dbg("  Iterations: %d\n", iteration);
  dbg("Is prime: %d\n", BN_is_prime_fasttest_ex(p, BN_prime_checks, NULL, 0, NULL));
  return p;
}

RSA *generate_key(BIGNUM *p1, BIGNUM *p2){
  dbg("generating key\n");
  //https://www.jianshu.com/p/9da812e0b8d0
  RSA *rsa = RSA_new();
  BIGNUM *n = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *d = BN_new();
  BIGNUM *gcd = BN_new();
  BIGNUM *phi = BN_new();
  BIGNUM *lambda = BN_new();
  BIGNUM *dmp1 = BN_new();
  BIGNUM *dmq1 = BN_new();
  BIGNUM *iqmp = BN_new();
  BIGNUM *p_minus_1 = BN_new();
  BIGNUM *q_minus_1 = BN_new();
  // n
  BN_mul(n, p1, p2, ctx);
  dbg("bit of N: %d\n", BN_num_bits(n));
  // e
  BN_set_word(e, 65537);
  // dmp1
  BN_sub(p_minus_1, p1, BN_1);
  BN_mod(dmp1, d, p_minus_1, ctx);
  // dmq1
  BN_sub(q_minus_1, p2, BN_1);
  BN_mod(dmq1, d, q_minus_1, ctx);
  // iqmp, inverse of q (p2) mod p (p1)
  BN_mod_inverse(iqmp, p2, p1, ctx);
  // d
  BN_gcd(gcd, p_minus_1, q_minus_1, ctx);
  BN_mul(phi, p_minus_1, q_minus_1, ctx);
  BN_div(lambda, NULL, phi, gcd, ctx);
  BN_mod_inverse(d, e, lambda, ctx);

  rsa -> p = p1;
  rsa -> q = p2;
  rsa -> n = n;
  rsa -> e = e;
  rsa -> d = d;
  rsa -> dmp1 = dmp1;
  rsa -> dmq1 = dmq1;
  rsa -> iqmp = iqmp;
  return rsa;
}

int is_prefix_BN(BIGNUM *t, BIGNUM *prefix, int shift){
  BIGNUM *t_prefix = BN_new();
  BN_rshift(t_prefix, t, shift);
  return !BN_cmp(t_prefix, prefix);
}

BIGNUM *generate_prime_with_prefix(char *prefix_hex){
  int shift_bit;
  int length;
  BIGNUM *prefix = BN_new();
  BIGNUM *t = BN_new();
  BIGNUM *range = BN_new();
  BIGNUM *floor = BN_new();
  BIGNUM *delta = BN_new();
  int found = 0;
  int iteration = 100;
  dbg("prefix:\n%s\n", prefix_hex);
  length = BN_hex2bn(&prefix, prefix_hex);
  dbg("length:\n%d\n", length);
  // left alignment
  shift_bit = (SMALL_PRIME_HEX_LEN - length) * 4;
  BN_lshift(floor, prefix, shift_bit);
  // TODO: change shift_bit
  BN_lshift(range, BN_1, shift_bit / 2);
  dbg("shift bit: %d\n", shift_bit);
  while (iteration) {
    BN_rand_range(delta, range);
    BN_add(t, floor, delta);
    while(is_prefix_BN(t, prefix, shift_bit)) {
      if (BN_is_prime_fasttest_ex(t, BN_prime_checks, NULL, 1, NULL)){
        found = 1;
        break;
      }
      BN_add_word(t, 1);
    }
    if (found) break;
    iteration--;
  }
  if (found) return t;
  else exit(0);
}

void send_encrypted_msg(char* prefix, unsigned char* msg, int len){
  printf("%s\n", prefix);
  for (int i = 0; i < len; i++)
    printf("%02x", msg[i]);
  printf("\n");
}

int recv_answer() {
  char *line = NULL;
  size_t len = 0;
  ssize_t msg_len = 0;
  if ((msg_len = getline(&line, &len, stdin)) && (msg_len > 0)){
    line[msg_len] = '\0';
    return atoi(line);
  }
  else return 0;
}

int validate_encrypted_question(RSA *rsa){
  unsigned char* encrypted;
  char question[50] = "";
  int size, question_len;
  int p, q, answer;
  srand(time(0));
  p = rand();
  q = rand();
  question_len = sprintf(question, "What's the sum of %d and %d?", p, q);
  encrypted = malloc(RSA_size(rsa));
  size = RSA_public_encrypt(question_len, (unsigned char*) question, (unsigned char*) encrypted, rsa, RSA_PKCS1_PADDING);
  send_encrypted_msg("Question: ", encrypted, size);
  answer = recv_answer();
  return answer == p + q;
}

void send_encrypted_flag(RSA *rsa){
  size_t len = 0;
  ssize_t flag_len;
  FILE *fp;
  char *flag = NULL;
  unsigned char* encrypted;
  fp = fopen(FLAGFILE, "r");
  flag_len = getline(&flag, &len, fp);
  fclose(fp);
  if (flag_len == -1)
    printf("Flag error. Please contact OOO\n");
  else{
    flag[flag_len-1] = '\0';
    encrypted = malloc(RSA_size(rsa));
    int size = RSA_public_encrypt(flag_len, (unsigned char*) flag, encrypted, rsa, RSA_PKCS1_PADDING);
#ifdef DEBUG
    printf("Your private key:\n");
    PEM_write_RSAPrivateKey(stdout, rsa, NULL, NULL, 0, 0, NULL);
    printf("message length: %d\n", size);
#endif
    send_encrypted_msg("Your flag message:", encrypted, size);
  }
}

void get_prime_prefix(char* prefix_hex){
  char *line = NULL;
  size_t len = 0;
  printf("Please input prefix IN HEX with length no more than %d: ", PREFIX_HEX_LEN);
  getline(&line, &len, stdin);
  strncpy(prefix_hex, line, PREFIX_HEX_LEN);
#ifdef DEBUG
  printf("%s\n", prefix_hex);
#endif
}

RSA *generate_rsa(BIGNUM *s){
  // generate rsa based on s
  BIGNUM *p1, *p2;
  p1 = generate_prime(s, NULL);
  p2 = generate_prime(s, p1);
  return generate_key(p1, p2);
}

void work() {
  RSA *rsa;
  BIGNUM *s;
  // 1. ask for prefix
  get_prime_prefix(prefix_hex);
  // 2. randomely generate s
  s = generate_prime_with_prefix(prefix_hex);
  // 3. randomly generate s_p and s_q for the prefix
  rsa = generate_rsa(s);
  if (rsa) {
    // printf("Your public key:\n%s", rsa_to_pem_pub(rsa));
    printf("Your public key:\n");
    PEM_write_RSAPublicKey(stdout, rsa);
#ifdef DEBUG
    printf("Your private key:\n");
    PEM_write_RSAPrivateKey(stdout, rsa, NULL, NULL, 0, 0, NULL);
#endif
    if (validate_encrypted_question(rsa))
      send_encrypted_flag(rsa);
    RSA_free(rsa);
  }
  BN_free(s);
}

int main(){
  init();
  work();
  clean();
  return 0;
}
