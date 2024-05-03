import argparse
import secrets
from collections import namedtuple
import gmpy2

Ciphertext = namedtuple("Ciphertext", ["u", "v"])

class EGPublicKey:
    def __init__(self):
        self.p = 5809605995369958062791915965639201402176612226902900533702900882779736177890990861472094774477339581147373410185646378328043729800750470098210924487866935059164371588168047540943981644516632755067501626434556398193186628990071248660819361205119793693985433297036118232914410171876807536457391277857011849897410207519105333355801121109356897459426271845471397952675959440793493071628394122780510124618488232602464649876850458861245784240929258426287699705312584509625419513463605155428017165714465363094021609290561084025893662561222573202082865797821865270991145082200656978177192827024538990239969175546190770645685893438011714430426409338676314743571154537142031573004276428701433036381801705308659830751190352946025482059931306571004727362479688415574702596946457770284148435989129632853918392117997472632693078113129886487399347796982772784615865232621289656944284216824611318709764535152507354116344703769998514148343807
        self.q = (self.p - 1) // 2
        self.g = 2
        self.pub = 5032211192984846990408701429388761348155974944215016627593232862860489774738396161903817522734582589517119044537822957747830475950445303428358476292029890778576711201862373835961348897868909735631176276762125062599389420777749269089180135212121952700242796406037862925126378350857180014062053433497750798490634479633897720062882243272386524831497984540262511191130713815698589096510733301132364433382585936881630912701216243339570496400568058642199441346064609694337255152974220076630375311201766437257300629552802076021673329771979568407713869154920625965747544315974046715008315332756468128551284013402941444926410819566101501125276569689617470101964946620809201916510634742981290297654173568905855358179800279647978236888241912497152074083566428273733423089220225767935521525626858983580927939038264424679205176403202861128221525526632375499867577678975938294346366979879794539674044342702244975337585955348901238205799835

    def encrypt(self, m: int) -> Ciphertext:
        if not 1 <= m < self.q:
            raise ValueError("Message not suitable for encryption")

        if gmpy2.legendre(m, self.p) != 1:
            m = self.p - m

        r = secrets.randbelow(self.q)
        u = gmpy2.powmod(self.g, r, self.p)
        blind = gmpy2.powmod(self.pub, r, self.p)
        v = (m * blind) % self.p
        return Ciphertext(u, v)

    def multiply(self, ct_1: Ciphertext, ct_2: Ciphertext) -> Ciphertext:
        u = (ct_1.u * ct_2.u) % self.p
        v = (ct_1.v * ct_2.v) % self.p
        return Ciphertext(u, v)

def main(ct: Ciphertext):
    pk = EGPublicKey()

    neutral_element = pk.encrypt(1)

    ct_res = pk.multiply(ct, neutral_element)

    assert ct.u != ct_res.u or ct.v != ct_res.v, "Ciphertext"
    print(ct_res.u)
    print(ct_res.v)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("u", help="the first ciphertext component", type=int)
    parser.add_argument("v", help="the second ciphertext component", type=int)
    args = parser.parse_args()
    main(Ciphertext(args.u, args.v))