import { verify } from "@node-rs/argon2";

async function main() {
  const hash =
    "$argon2id$v=19$m=19456,t=2,p=1$MogV8lvOoQQA7W0v7rui8g$tBpZW+CULdxw1X30gpvtPrms1YzkLrd8KREVnLBVfo8";

  const password = '.-p3nt4k1lL';

  const ok = await verify(hash, password);

  console.log(ok);
}

main();