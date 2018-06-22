extern crate integer_encoding;
extern crate crypto;
extern crate data_encoding;

use std::collections::HashMap;
use std::mem;
use std::borrow::BorrowMut;
use integer_encoding::VarInt;
use crypto::sha2::Sha256;
use crypto::digest::Digest;

#[derive(Debug, Clone)]
struct Sha256Hash ([u8;32]);  // for testing

#[derive(Debug)]
struct InnerNode (HashMap<u8,Box<Node>>);

#[derive(Debug)]
struct Leaf {
    remaining_key: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Debug)]
struct Tree {
    root: Option<Node>,
}

impl Default for Tree {
    fn default() -> Self {
        Tree {
            root: None,
        }
    }
}

#[derive(Debug)]
enum Node {
    InnerNode(InnerNode),
    Leaf(Leaf),
}

trait Serializable {
    fn serialize(&self) -> Vec<u8>;
}

impl Serializable for Leaf {
    fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(0x02);  // Leaf type

        let mut inside = Vec::new();

        inside.extend( self.remaining_key.len().encode_var_vec() );
        inside.extend( self.remaining_key.clone() );

        inside.extend( self.value.len().encode_var_vec() );
        inside.extend( self.value.clone() );

        result.extend( inside.len().encode_var_vec() );
        result.extend( inside);

        result
    }
}

impl Serializable for Node {
    fn serialize(&self) -> Vec<u8> {
        match self {
            Node::InnerNode(inner) => inner.serialize(),
            Node::Leaf(leaf) => leaf.serialize(),
        }
    }
}


impl Serializable for InnerNode {
    fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(0x01);  // InnerNode type

        let mut inside = Vec::new();
        let map = &self.0;
        for i in 0u8..=255 {
            match map.get(&i) {
                Some(node) => {
                    let vec = node.serialize();
                    inside.extend(vec.len().encode_var_vec());
                    inside.extend(vec);
                },
                None => inside.push(0x00),
            };
        }
        result.extend( inside.len().encode_var_vec() );
        result.extend( inside);

        result
    }
}


trait Hashable {
    fn hash(&self) -> Sha256Hash;
}

impl Hashable for Leaf {  //this should be a dependent trait of serializable!
    fn hash(&self) -> Sha256Hash {
        hash(self.serialize())
    }
}
impl Hashable  for InnerNode {  //this should be a dependent trait of serializable!
    fn hash(&self) -> Sha256Hash {
        hash(self.serialize())
    }
}

fn hash(vec : Vec<u8>) -> Sha256Hash {
    let mut hashed = [0u8;32];
    let mut hasher = Sha256::new();
    hasher.input(&vec[..]);
    hasher.result(&mut hashed);
    Sha256Hash(hashed)
}

impl Node {

    fn add( &mut self, key: Vec<u8> , value: Vec<u8>) {
        match self {
            Node::Leaf(leaf) => {
                let mut map = HashMap::new();
                let(a,b) = key.split_at(1);
                map.insert(a[0], Box::new(Node::Leaf(Leaf {
                    remaining_key: b.to_vec(),
                    value: value,
                })));

                let a = leaf.remaining_key.remove(0);
                map.insert(a, Box::new(Node::Leaf(Leaf {
                    remaining_key: leaf.remaining_key.clone(),
                    value: leaf.value.clone(),
                })));
                let new_node = Node::InnerNode(InnerNode(map));
                mem::replace(self, new_node);
            },
            Node::InnerNode(ref mut inner) => {
                let (a, b) = key.split_at(1);
                let mut map = inner.0.borrow_mut();
                match map.remove(&a[0]) {
                    Some(mut node) => {
                        node.add(b.to_vec(),value);
                        map.insert(a[0], node);
                    },
                    None => {
                        let new_node = Node::Leaf(Leaf {
                            remaining_key: b.to_vec(),
                            value: value,
                        });
                        map.insert(a[0], Box::new(new_node));
                    }
                }
            },
        }
    }

    fn get(&self, key: Vec<u8>)  -> Option<Vec<u8>> {
        match self {
            Node::Leaf(leaf) => {
                Some(leaf.value.clone())
            },
            Node::InnerNode(inner) => {
                let (a, b) = key.split_at(1);
                match inner.0.get(&a[0]) {
                    None => None,
                    Some(node) => node.get(b.to_vec()),
                }
            }
        }
    }
}



impl Tree {
    pub fn add(&mut self, key: &Sha256Hash , value: Vec<u8>) {
        match self.root {
            None => {
                let new_node = Node::Leaf(Leaf {
                    remaining_key: key.0.to_vec(),
                    value: value,
                });
                mem::replace(&mut self.root, Some(new_node));
            },
            Some(ref mut root) => {
                root.add(key.0.to_vec(), value);
            }
        }
    }

    pub fn get(&self, key: &Sha256Hash) -> Option<Vec<u8>> {
        match self.root {
            None => None,
            Some(ref root) => root.get(key.0.to_vec()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }
}

impl Serializable for Tree {
    fn serialize(&self) -> Vec<u8> {
        match &self.root {
            None => vec![0x00],
            Some(root) => root.serialize()
        }
    }
}


fn main() {
    let mut tree= Tree::default();
    let a1 = Sha256Hash([0u8;32]);
    let a2 = [0x02].to_vec();
    tree.add(&a1, a2);
    println!("{:?}", tree.get(&a1));
    println!("{:?}", tree.is_empty());
}

#[cfg(test)]
mod tests {
    use ::*;
    use integer_encoding::VarInt;
    use data_encoding::HEXLOWER;


    #[test]
    fn test_tree() {
        let mut tree= Tree::default();
        assert!(tree.is_empty());
        let a1 = Sha256Hash([0u8;32]);
        assert!(tree.get(&a1).is_none());
        println!("{:?}",tree.serialize());

        let a2 = [0x02].to_vec();
        tree.add(&a1, a2.clone());
        assert!(!tree.is_empty());
        assert_eq!(tree.get(&a1).unwrap(), a2);
        println!("{:?}",tree.serialize());

        let b1 = Sha256Hash([1u8;32]);
        let  b2 = [0x12].to_vec();
        tree.add(&b1, b2.clone());
        assert_eq!(tree.get(&a1).unwrap(), a2);
        assert_eq!(tree.get(&b1).unwrap(), b2);
        println!("{:?}",tree);
        println!("{:?}",tree.serialize());

        let c1 = Sha256Hash([2u8;32]);
        let c2 = [0x01].to_vec();
        tree.add(&c1, c2.clone());
        assert_eq!(tree.get(&a1).unwrap(), a2);
        assert_eq!(tree.get(&b1).unwrap(), b2);
        assert_eq!(tree.get(&c1).unwrap(), c2);


        let d1 = Sha256Hash([3u8;32]);
        let d2 = [0x31].to_vec();
        tree.add(&d1, d2.clone());
        assert_eq!(tree.get(&a1).unwrap(), a2);
        assert_eq!(tree.get(&b1).unwrap(), b2);
        assert_eq!(tree.get(&c1).unwrap(), c2);
        assert_eq!(tree.get(&d1).unwrap(), d2);

        println!("{:?}",tree.serialize());
    }

    #[test]
    fn test_varint() {
        let a = 0usize;
        let x = a.encode_var_vec();
        assert_eq!(&x[..],&[0x00]);
    }

    #[test]
    fn test_serialize() {
        let leaf = Leaf {
            remaining_key: [0x01].to_vec(),
            value: [0x02].to_vec(),
        };
        assert_eq!(leaf.serialize(), [0x02,0x04,0x01,0x01,0x01,0x02]);
    }

    #[test]
    fn test_hash() {
        let leaf = Leaf {
            remaining_key: [0x01].to_vec(),
            value: [0x02].to_vec(),
        };
        assert_eq!(leaf.serialize(), [0x02,0x04,0x01,0x01,0x01,0x02]);
        let b = HEXLOWER.decode("f5c058ec832bd6b8e5cb6f1bcdb60dfdcb44d397ba9f95d18a79cd0db92e4dc1".as_bytes()).unwrap();

        assert_eq!(leaf.hash().0.to_vec(), b);
    }

}
