//! Decoding trees for Bitcoin and Elements.
//! Should be replaced with generic flow when issue with BitIter rewind would be resolved.
use quote::quote;

use crate::StaticTokenInfo;

pub(crate) fn bitcoin_decode_tree(
    custom_tree: proc_macro2::TokenStream,
    base_type: &syn::Path,
) -> proc_macro2::TokenStream {
    let enum_ident = StaticTokenInfo::enum_ident();

    quote! {
        decode_bits!(bits, {
            0 => {
                0 => {#enum_ident::BaseJets(#base_type::Verify)},
                1 => {
                    0 => {
                        0 => {
                            0 => {#enum_ident::BaseJets(#base_type::Low1)},
                            1 => {
                                0 => {
                                    0 => {},
                                    1 => {#enum_ident::BaseJets(#base_type::Low8)}
                                },
                                1 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {#enum_ident::BaseJets(#base_type::Low16)},
                                                1 => {#enum_ident::BaseJets(#base_type::Low32)}
                                            },
                                            1 => {
                                                0 => {#enum_ident::BaseJets(#base_type::Low64)},
                                                1 => {}
                                            }
                                        },
                                        1 => {}
                                    },
                                    1 => {}
                                }
                            }
                        },
                        1 => {
                            0 => {#enum_ident::BaseJets(#base_type::High1)},
                            1 => {
                                0 => {
                                    0 => {},
                                    1 => {#enum_ident::BaseJets(#base_type::High8)}
                                },
                                1 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {#enum_ident::BaseJets(#base_type::High16)},
                                                1 => {#enum_ident::BaseJets(#base_type::High32)}
                                            },
                                            1 => {
                                                0 => {#enum_ident::BaseJets(#base_type::High64)},
                                                1 => {}
                                            }
                                        },
                                        1 => {}
                                    },
                                    1 => {}
                                }
                            }
                        }
                    },
                    1 => {
                        0 => {
                            0 => {
                                0 => {
                                    0 => {
                                        0 => {#enum_ident::BaseJets(#base_type::Complement1)},
                                        1 => {
                                            0 => {
                                                0 => {},
                                                1 => {#enum_ident::BaseJets(#base_type::Complement8)}
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::Complement16)},
                                                            1 => {#enum_ident::BaseJets(#base_type::Complement32)}
                                                        },
                                                        1 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::Complement64)},
                                                            1 => {}
                                                        }
                                                    },
                                                    1 => {}
                                                },
                                                1 => {}
                                            }
                                        }
                                    },
                                    1 => {
                                        0 => {#enum_ident::BaseJets(#base_type::And1)},
                                        1 => {
                                            0 => {
                                                0 => {},
                                                1 => {#enum_ident::BaseJets(#base_type::And8)}
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::And16)},
                                                            1 => {#enum_ident::BaseJets(#base_type::And32)}
                                                        },
                                                        1 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::And64)},
                                                            1 => {}
                                                        }
                                                    },
                                                    1 => {}
                                                },
                                                1 => {}
                                            }
                                        }
                                    }
                                },
                                1 => {
                                    0 => {
                                        0 => {#enum_ident::BaseJets(#base_type::Or1)},
                                        1 => {
                                            0 => {
                                                0 => {},
                                                1 => {#enum_ident::BaseJets(#base_type::Or8)}
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::Or16)},
                                                            1 => {#enum_ident::BaseJets(#base_type::Or32)}
                                                        },
                                                        1 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::Or64)},
                                                            1 => {}
                                                        }
                                                    },
                                                    1 => {}
                                                },
                                                1 => {}
                                            }
                                        }
                                    },
                                    1 => {
                                        0 => {#enum_ident::BaseJets(#base_type::Xor1)},
                                        1 => {
                                            0 => {
                                                0 => {},
                                                1 => {#enum_ident::BaseJets(#base_type::Xor8)}
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::Xor16)},
                                                            1 => {#enum_ident::BaseJets(#base_type::Xor32)}
                                                        },
                                                        1 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::Xor64)},
                                                            1 => {}
                                                        }
                                                    },
                                                    1 => {}
                                                },
                                                1 => {}
                                            }
                                        }
                                    }
                                }
                            },
                            1 => {
                                0 => {
                                    0 => {
                                        0 => {
                                            0 => {#enum_ident::BaseJets(#base_type::Maj1)},
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {#enum_ident::BaseJets(#base_type::Maj8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::Maj16)},
                                                                1 => {#enum_ident::BaseJets(#base_type::Maj32)}
                                                            },
                                                            1 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::Maj64)},
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        },
                                        1 => {
                                            0 => {#enum_ident::BaseJets(#base_type::XorXor1)},
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {#enum_ident::BaseJets(#base_type::XorXor8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::XorXor16)},
                                                                1 => {#enum_ident::BaseJets(#base_type::XorXor32)}
                                                            },
                                                            1 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::XorXor64)},
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        }
                                    },
                                    1 => {
                                        0 => {
                                            0 => {#enum_ident::BaseJets(#base_type::Ch1)},
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {#enum_ident::BaseJets(#base_type::Ch8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::Ch16)},
                                                                1 => {#enum_ident::BaseJets(#base_type::Ch32)}
                                                            },
                                                            1 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::Ch64)},
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        },
                                        1 => {
                                            0 => {#enum_ident::BaseJets(#base_type::Some1)},
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {#enum_ident::BaseJets(#base_type::Some8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::Some16)},
                                                                1 => {#enum_ident::BaseJets(#base_type::Some32)}
                                                            },
                                                            1 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::Some64)},
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        }
                                    }
                                },
                                1 => {
                                    0 => {
                                        0 => {
                                            0 => {},
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {#enum_ident::BaseJets(#base_type::All8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::All16)},
                                                                1 => {#enum_ident::BaseJets(#base_type::All32)}
                                                            },
                                                            1 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::All64)},
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        },
                                        1 => {
                                            0 => {#enum_ident::BaseJets(#base_type::Eq1)},
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {#enum_ident::BaseJets(#base_type::Eq8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::Eq16)},
                                                                1 => {#enum_ident::BaseJets(#base_type::Eq32)}
                                                            },
                                                            1 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::Eq64)},
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::Eq256)},
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        }
                                    },
                                    1 => {
                                        0 => {
                                            0 => {
                                                0 => {},
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {#enum_ident::BaseJets(#base_type::FullLeftShift8_1)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::FullLeftShift16_1)},
                                                                    1 => {#enum_ident::BaseJets(#base_type::FullLeftShift32_1)}
                                                                },
                                                                1 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::FullLeftShift64_1)},
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::FullLeftShift8_2)},
                                                                1 => {#enum_ident::BaseJets(#base_type::FullLeftShift16_2)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::FullLeftShift32_2)},
                                                                            1 => {#enum_ident::BaseJets(#base_type::FullLeftShift64_2)}
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {#enum_ident::BaseJets(#base_type::FullLeftShift8_4)},
                                                        1 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::FullLeftShift16_4)},
                                                                1 => {#enum_ident::BaseJets(#base_type::FullLeftShift32_4)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::FullLeftShift64_4)},
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::FullLeftShift16_8)},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::FullLeftShift32_8)},
                                                                            1 => {#enum_ident::BaseJets(#base_type::FullLeftShift64_8)}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::FullLeftShift32_16)},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::FullLeftShift64_16)},
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::FullLeftShift64_32)},
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        },
                                        1 => {
                                            0 => {
                                                0 => {},
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {#enum_ident::BaseJets(#base_type::FullRightShift8_1)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::FullRightShift16_1)},
                                                                    1 => {#enum_ident::BaseJets(#base_type::FullRightShift32_1)}
                                                                },
                                                                1 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::FullRightShift64_1)},
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::FullRightShift8_2)},
                                                                1 => {#enum_ident::BaseJets(#base_type::FullRightShift16_2)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::FullRightShift32_2)},
                                                                            1 => {#enum_ident::BaseJets(#base_type::FullRightShift64_2)}
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {#enum_ident::BaseJets(#base_type::FullRightShift8_4)},
                                                        1 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::FullRightShift16_4)},
                                                                1 => {#enum_ident::BaseJets(#base_type::FullRightShift32_4)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::FullRightShift64_4)},
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::FullRightShift16_8)},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::FullRightShift32_8)},
                                                                            1 => {#enum_ident::BaseJets(#base_type::FullRightShift64_8)}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::FullRightShift32_16)},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::FullRightShift64_16)},
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::FullRightShift64_32)},
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        1 => {
                            0 => {
                                0 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {#enum_ident::BaseJets(#base_type::Leftmost8_1)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::Leftmost16_1)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::Leftmost32_1)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::Leftmost64_1)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::Leftmost8_2)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::Leftmost16_2)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Leftmost32_2)},
                                                                                            1 => {#enum_ident::BaseJets(#base_type::Leftmost64_2)}
                                                                                        },
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::Leftmost8_4)},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::Leftmost16_4)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::Leftmost32_4)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Leftmost64_4)},
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::Leftmost16_8)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Leftmost32_8)},
                                                                                            1 => {#enum_ident::BaseJets(#base_type::Leftmost64_8)}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::Leftmost32_16)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Leftmost64_16)},
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::Leftmost64_32)},
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {#enum_ident::BaseJets(#base_type::Rightmost8_1)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::Rightmost16_1)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::Rightmost32_1)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::Rightmost64_1)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::Rightmost8_2)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::Rightmost16_2)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Rightmost32_2)},
                                                                                            1 => {#enum_ident::BaseJets(#base_type::Rightmost64_2)}
                                                                                        },
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::Rightmost8_4)},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::Rightmost16_4)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::Rightmost32_4)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Rightmost64_4)},
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::Rightmost16_8)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Rightmost32_8)},
                                                                                            1 => {#enum_ident::BaseJets(#base_type::Rightmost64_8)}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::Rightmost32_16)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Rightmost64_16)},
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::Rightmost64_32)},
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {#enum_ident::BaseJets(#base_type::LeftPadLow1_8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftPadLow1_16)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::LeftPadLow1_32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftPadLow1_64)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftPadLow8_16)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::LeftPadLow8_32)},
                                                                                            1 => {#enum_ident::BaseJets(#base_type::LeftPadLow8_64)}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftPadLow16_32)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::LeftPadLow16_64)},
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftPadLow32_64)},
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {#enum_ident::BaseJets(#base_type::LeftPadHigh1_8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftPadHigh1_16)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::LeftPadHigh1_32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftPadHigh1_64)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftPadHigh8_16)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::LeftPadHigh8_32)},
                                                                                            1 => {#enum_ident::BaseJets(#base_type::LeftPadHigh8_64)}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftPadHigh16_32)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::LeftPadHigh16_64)},
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftPadHigh32_64)},
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {#enum_ident::BaseJets(#base_type::LeftExtend1_8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftExtend1_16)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::LeftExtend1_32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftExtend1_64)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftExtend8_16)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::LeftExtend8_32)},
                                                                                            1 => {#enum_ident::BaseJets(#base_type::LeftExtend8_64)}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftExtend16_32)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::LeftExtend16_64)},
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftExtend32_64)},
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {#enum_ident::BaseJets(#base_type::RightPadLow1_8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::RightPadLow1_16)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::RightPadLow1_32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::RightPadLow1_64)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::RightPadLow8_16)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::RightPadLow8_32)},
                                                                                            1 => {#enum_ident::BaseJets(#base_type::RightPadLow8_64)}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::RightPadLow16_32)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::RightPadLow16_64)},
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::RightPadLow32_64)},
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {#enum_ident::BaseJets(#base_type::RightPadHigh1_8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::RightPadHigh1_16)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::RightPadHigh1_32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::RightPadHigh1_64)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::RightPadHigh8_16)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::RightPadHigh8_32)},
                                                                                            1 => {#enum_ident::BaseJets(#base_type::RightPadHigh8_64)}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::RightPadHigh16_32)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::RightPadHigh16_64)},
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::RightPadHigh32_64)},
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {},
                                                            1 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::RightExtend8_16)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::RightExtend8_32)},
                                                                                            1 => {#enum_ident::BaseJets(#base_type::RightExtend8_64)}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::RightExtend16_32)},
                                                                                    1 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::RightExtend16_64)},
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    }
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::RightExtend32_64)},
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {#enum_ident::BaseJets(#base_type::LeftShiftWith8)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::LeftShiftWith16)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::LeftShiftWith32)}
                                                                            },
                                                                            1 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::LeftShiftWith64)},
                                                                                1 => {}
                                                                            }
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {},
                                                            1 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {#enum_ident::BaseJets(#base_type::RightShiftWith8)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::RightShiftWith16)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::RightShiftWith32)}
                                                                            },
                                                                            1 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::RightShiftWith64)},
                                                                                1 => {}
                                                                            }
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {#enum_ident::BaseJets(#base_type::LeftShift8)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::LeftShift16)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::LeftShift32)}
                                                                            },
                                                                            1 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::LeftShift64)},
                                                                                1 => {}
                                                                            }
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {},
                                                            1 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {#enum_ident::BaseJets(#base_type::RightShift8)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::RightShift16)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::RightShift32)}
                                                                            },
                                                                            1 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::RightShift64)},
                                                                                1 => {}
                                                                            }
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {#enum_ident::BaseJets(#base_type::LeftRotate8)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::LeftRotate16)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::LeftRotate32)}
                                                                            },
                                                                            1 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::LeftRotate64)},
                                                                                1 => {}
                                                                            }
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {},
                                                            1 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {#enum_ident::BaseJets(#base_type::RightRotate8)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::RightRotate16)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::RightRotate32)}
                                                                            },
                                                                            1 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::RightRotate64)},
                                                                                1 => {}
                                                                            }
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        }
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        },
                                        1 => {}
                                    },
                                    1 => {}
                                },
                                1 => {}
                            },
                            1 => {}
                        }
                    }
                }
            },
            1 => {
                0 => {
                    0 => {
                        0 => {
                            0 => {},
                            1 => {
                                0 => {
                                    0 => {},
                                    1 => {#enum_ident::BaseJets(#base_type::One8)}
                                },
                                1 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {#enum_ident::BaseJets(#base_type::One16)},
                                                1 => {#enum_ident::BaseJets(#base_type::One32)}
                                            },
                                            1 => {
                                                0 => {#enum_ident::BaseJets(#base_type::One64)},
                                                1 => {}
                                            }
                                        },
                                        1 => {}
                                    },
                                    1 => {}
                                }
                            }
                        },
                        1 => {
                            0 => {
                                0 => {
                                    0 => {},
                                    1 => {
                                        0 => {
                                            0 => {},
                                            1 => {#enum_ident::BaseJets(#base_type::FullAdd8)}
                                        },
                                        1 => {
                                            0 => {
                                                0 => {
                                                    0 => {
                                                        0 => {#enum_ident::BaseJets(#base_type::FullAdd16)},
                                                        1 => {#enum_ident::BaseJets(#base_type::FullAdd32)}
                                                    },
                                                    1 => {
                                                        0 => {#enum_ident::BaseJets(#base_type::FullAdd64)},
                                                        1 => {}
                                                    }
                                                },
                                                1 => {}
                                            },
                                            1 => {}
                                        }
                                    }
                                },
                                1 => {
                                    0 => {},
                                    1 => {
                                        0 => {
                                            0 => {},
                                            1 => {#enum_ident::BaseJets(#base_type::Add8)}
                                        },
                                        1 => {
                                            0 => {
                                                0 => {
                                                    0 => {
                                                        0 => {#enum_ident::BaseJets(#base_type::Add16)},
                                                        1 => {#enum_ident::BaseJets(#base_type::Add32)}
                                                    },
                                                    1 => {
                                                        0 => {#enum_ident::BaseJets(#base_type::Add64)},
                                                        1 => {}
                                                    }
                                                },
                                                1 => {}
                                            },
                                            1 => {}
                                        }
                                    }
                                }
                            },
                            1 => {
                                0 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {},
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {#enum_ident::BaseJets(#base_type::FullIncrement8)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::FullIncrement16)},
                                                                    1 => {#enum_ident::BaseJets(#base_type::FullIncrement32)}
                                                                },
                                                                1 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::FullIncrement64)},
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {},
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {#enum_ident::BaseJets(#base_type::Increment8)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::Increment16)},
                                                                    1 => {#enum_ident::BaseJets(#base_type::Increment32)}
                                                                },
                                                                1 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::Increment64)},
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            }
                                        },
                                        1 => {
                                            0 => {},
                                            1 => {
                                                0 => {},
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {#enum_ident::BaseJets(#base_type::FullSubtract8)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::FullSubtract16)},
                                                                    1 => {#enum_ident::BaseJets(#base_type::FullSubtract32)}
                                                                },
                                                                1 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::FullSubtract64)},
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            }
                                        }
                                    },
                                    1 => {
                                        0 => {
                                            0 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {#enum_ident::BaseJets(#base_type::Subtract8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::Subtract16)},
                                                                        1 => {#enum_ident::BaseJets(#base_type::Subtract32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::Subtract64)},
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {},
                                                    1 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {#enum_ident::BaseJets(#base_type::Negate8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::Negate16)},
                                                                        1 => {#enum_ident::BaseJets(#base_type::Negate32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::Negate64)},
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {#enum_ident::BaseJets(#base_type::FullDecrement8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::FullDecrement16)},
                                                                        1 => {#enum_ident::BaseJets(#base_type::FullDecrement32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::FullDecrement64)},
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {},
                                                    1 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {#enum_ident::BaseJets(#base_type::Decrement8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::Decrement16)},
                                                                        1 => {#enum_ident::BaseJets(#base_type::Decrement32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::Decrement64)},
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    }
                                                }
                                            }
                                        },
                                        1 => {
                                            0 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {#enum_ident::BaseJets(#base_type::FullMultiply8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::FullMultiply16)},
                                                                        1 => {#enum_ident::BaseJets(#base_type::FullMultiply32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::FullMultiply64)},
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {},
                                                    1 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {#enum_ident::BaseJets(#base_type::Multiply8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::Multiply16)},
                                                                        1 => {#enum_ident::BaseJets(#base_type::Multiply32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::Multiply64)},
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {#enum_ident::BaseJets(#base_type::IsZero8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::IsZero16)},
                                                                        1 => {#enum_ident::BaseJets(#base_type::IsZero32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::IsZero64)},
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {},
                                                    1 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {#enum_ident::BaseJets(#base_type::IsOne8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::IsOne16)},
                                                                        1 => {#enum_ident::BaseJets(#base_type::IsOne32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::IsOne64)},
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                1 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {#enum_ident::BaseJets(#base_type::Le8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Le16)},
                                                                                        1 => {#enum_ident::BaseJets(#base_type::Le32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Le64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {#enum_ident::BaseJets(#base_type::Lt8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Lt16)},
                                                                                        1 => {#enum_ident::BaseJets(#base_type::Lt32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Lt64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {#enum_ident::BaseJets(#base_type::Min8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Min16)},
                                                                                        1 => {#enum_ident::BaseJets(#base_type::Min32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Min64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {#enum_ident::BaseJets(#base_type::Max8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Max16)},
                                                                                        1 => {#enum_ident::BaseJets(#base_type::Max32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Max64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {#enum_ident::BaseJets(#base_type::Median8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Median16)},
                                                                                        1 => {#enum_ident::BaseJets(#base_type::Median32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Median64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {},
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::DivMod128_64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {#enum_ident::BaseJets(#base_type::DivMod8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::DivMod16)},
                                                                                        1 => {#enum_ident::BaseJets(#base_type::DivMod32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::DivMod64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {#enum_ident::BaseJets(#base_type::Divide8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Divide16)},
                                                                                        1 => {#enum_ident::BaseJets(#base_type::Divide32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Divide64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {#enum_ident::BaseJets(#base_type::Modulo8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Modulo16)},
                                                                                        1 => {#enum_ident::BaseJets(#base_type::Modulo32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Modulo64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {#enum_ident::BaseJets(#base_type::Divides8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Divides16)},
                                                                                        1 => {#enum_ident::BaseJets(#base_type::Divides32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Divides64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                },
                                                1 => {}
                                            },
                                            1 => {}
                                        },
                                        1 => {}
                                    },
                                    1 => {}
                                }
                            }
                        }
                    },
                    1 => {
                        0 => {
                            0 => {#enum_ident::BaseJets(#base_type::Sha256Block)},
                            1 => {
                                0 => {
                                    0 => {#enum_ident::BaseJets(#base_type::Sha256Iv)},
                                    1 => {
                                        0 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add1)},
                                        1 => {
                                            0 => {
                                                0 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add2)},
                                                1 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add4)}
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add8)},
                                                            1 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add16)}
                                                        },
                                                        1 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add32)},
                                                            1 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add64)}
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add128)},
                                                                1 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add256)}
                                                            },
                                                            1 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add512)},
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {}
                                                    }
                                                },
                                                1 => {}
                                            }
                                        }
                                    }
                                },
                                1 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8AddBuffer511)},
                                                1 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Finalize)}
                                            },
                                            1 => {
                                                0 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Init)},
                                                1 => {}
                                            }
                                        },
                                        1 => {}
                                    },
                                    1 => {}
                                }
                            }
                        },
                        1 => {}
                    }
                },
                1 => {
                    0 => {
                        0 => {
                            0 => {
                                0 => {
                                    0 => {
                                        0 => {#enum_ident::BaseJets(#base_type::PointVerify1)},
                                        1 => {}
                                    },
                                    1 => {
                                        0 => {
                                            0 => {#enum_ident::BaseJets(#base_type::Decompress)},
                                            1 => {
                                                0 => {#enum_ident::BaseJets(#base_type::LinearVerify1)},
                                                1 => {}
                                            }
                                        },
                                        1 => {
                                            0 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::LinearCombination1)},
                                                            1 => {}
                                                        },
                                                        1 => {#enum_ident::BaseJets(#base_type::Scale)}
                                                    },
                                                    1 => {
                                                        0 => {#enum_ident::BaseJets(#base_type::Generate)},
                                                        1 => {#enum_ident::BaseJets(#base_type::GejInfinity)}
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::GejNormalize)},
                                                            1 => {#enum_ident::BaseJets(#base_type::GejNegate)}
                                                        },
                                                        1 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::GeNegate)},
                                                            1 => {#enum_ident::BaseJets(#base_type::GejDouble)}
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::GejAdd)},
                                                            1 => {#enum_ident::BaseJets(#base_type::GejGeAddEx)}
                                                        },
                                                        1 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::GejGeAdd)},
                                                            1 => {#enum_ident::BaseJets(#base_type::GejRescale)}
                                                        }
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::GejIsInfinity)},
                                                                            1 => {#enum_ident::BaseJets(#base_type::GejEquiv)}
                                                                        },
                                                                        1 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::GejGeEquiv)},
                                                                            1 => {#enum_ident::BaseJets(#base_type::GejXEquiv)}
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::GejYIsOdd)},
                                                                            1 => {#enum_ident::BaseJets(#base_type::GejIsOnCurve)}
                                                                        },
                                                                        1 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::GeIsOnCurve)},
                                                                            1 => {#enum_ident::BaseJets(#base_type::ScalarNormalize)}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::ScalarNegate)},
                                                                            1 => {#enum_ident::BaseJets(#base_type::ScalarAdd)}
                                                                        },
                                                                        1 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::ScalarSquare)},
                                                                            1 => {#enum_ident::BaseJets(#base_type::ScalarMultiply)}
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::ScalarMultiplyLambda)},
                                                                            1 => {#enum_ident::BaseJets(#base_type::ScalarInvert)}
                                                                        },
                                                                        1 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::ScalarIsZero)},
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {
                                                                                0 => {},
                                                                                1 => {#enum_ident::BaseJets(#base_type::FeNormalize)}
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::FeNegate)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::FeAdd)}
                                                                            },
                                                                            1 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::FeSquare)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::FeMultiply)}
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::FeMultiplyBeta)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::FeInvert)}
                                                                            },
                                                                            1 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::FeSquareRoot)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::FeIsZero)}
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::FeIsOdd)},
                                                                                1 => {}
                                                                            },
                                                                            1 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::HashToCurve)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::Swu)}
                                                                            }
                                                                        }
                                                                    }
                                                                },
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                },
                                                1 => {}
                                            }
                                        }
                                    }
                                },
                                1 => {
                                    0 => {#enum_ident::BaseJets(#base_type::CheckSigVerify)},
                                    1 => {
                                        0 => {
                                            0 => {#enum_ident::BaseJets(#base_type::Bip0340Verify)},
                                            1 => {}
                                        },
                                        1 => {}
                                    }
                                }
                            },
                            1 => {
                                0 => {},
                                1 => {
                                    0 => {#enum_ident::BaseJets(#base_type::ParseLock)},
                                    1 => {
                                        0 => {
                                            0 => {#enum_ident::BaseJets(#base_type::ParseSequence)},
                                            1 => {#enum_ident::BaseJets(#base_type::TapdataInit)}
                                        },
                                        1 => {}
                                    }
                                }
                            }
                        },
                        1 => {}
                    },
                    1 => {
                        0 => {},
                        1 => {
                            #custom_tree
                        }
                    }
                }
            }
        })
    }
}

pub(crate) fn elements_decode_tree(
    custom_tree: proc_macro2::TokenStream,
    base_type: &syn::Path,
) -> proc_macro2::TokenStream {
    let enum_ident = StaticTokenInfo::enum_ident();

    quote! {
        decode_bits!(bits, {
            0 => {
                0 => {
                    0 => {#enum_ident::BaseJets(#base_type::Verify)},
                    1 => {
                        0 => {
                            0 => {
                                0 => {#enum_ident::BaseJets(#base_type::Low1)},
                                1 => {
                                    0 => {
                                        0 => {},
                                        1 => {#enum_ident::BaseJets(#base_type::Low8)}
                                    },
                                    1 => {
                                        0 => {
                                            0 => {
                                                0 => {
                                                    0 => {#enum_ident::BaseJets(#base_type::Low16)},
                                                    1 => {#enum_ident::BaseJets(#base_type::Low32)}
                                                },
                                                1 => {
                                                    0 => {#enum_ident::BaseJets(#base_type::Low64)},
                                                    1 => {}
                                                }
                                            },
                                            1 => {}
                                        },
                                        1 => {}
                                    }
                                }
                            },
                            1 => {
                                0 => {#enum_ident::BaseJets(#base_type::High1)},
                                1 => {
                                    0 => {
                                        0 => {},
                                        1 => {#enum_ident::BaseJets(#base_type::High8)}
                                    },
                                    1 => {
                                        0 => {
                                            0 => {
                                                0 => {
                                                    0 => {#enum_ident::BaseJets(#base_type::High16)},
                                                    1 => {#enum_ident::BaseJets(#base_type::High32)}
                                                },
                                                1 => {
                                                    0 => {#enum_ident::BaseJets(#base_type::High64)},
                                                    1 => {}
                                                }
                                            },
                                            1 => {}
                                        },
                                        1 => {}
                                    }
                                }
                            }
                        },
                        1 => {
                            0 => {
                                0 => {
                                    0 => {
                                        0 => {
                                            0 => {#enum_ident::BaseJets(#base_type::Complement1)},
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {#enum_ident::BaseJets(#base_type::Complement8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::Complement16)},
                                                                1 => {#enum_ident::BaseJets(#base_type::Complement32)}
                                                            },
                                                            1 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::Complement64)},
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        },
                                        1 => {
                                            0 => {#enum_ident::BaseJets(#base_type::And1)},
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {#enum_ident::BaseJets(#base_type::And8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::And16)},
                                                                1 => {#enum_ident::BaseJets(#base_type::And32)}
                                                            },
                                                            1 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::And64)},
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        }
                                    },
                                    1 => {
                                        0 => {
                                            0 => {#enum_ident::BaseJets(#base_type::Or1)},
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {#enum_ident::BaseJets(#base_type::Or8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::Or16)},
                                                                1 => {#enum_ident::BaseJets(#base_type::Or32)}
                                                            },
                                                            1 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::Or64)},
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        },
                                        1 => {
                                            0 => {#enum_ident::BaseJets(#base_type::Xor1)},
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {#enum_ident::BaseJets(#base_type::Xor8)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::Xor16)},
                                                                1 => {#enum_ident::BaseJets(#base_type::Xor32)}
                                                            },
                                                            1 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::Xor64)},
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        }
                                    }
                                },
                                1 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {#enum_ident::BaseJets(#base_type::Maj1)},
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {#enum_ident::BaseJets(#base_type::Maj8)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::Maj16)},
                                                                    1 => {#enum_ident::BaseJets(#base_type::Maj32)}
                                                                },
                                                                1 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::Maj64)},
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {#enum_ident::BaseJets(#base_type::XorXor1)},
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {#enum_ident::BaseJets(#base_type::XorXor8)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::XorXor16)},
                                                                    1 => {#enum_ident::BaseJets(#base_type::XorXor32)}
                                                                },
                                                                1 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::XorXor64)},
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            }
                                        },
                                        1 => {
                                            0 => {
                                                0 => {#enum_ident::BaseJets(#base_type::Ch1)},
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {#enum_ident::BaseJets(#base_type::Ch8)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::Ch16)},
                                                                    1 => {#enum_ident::BaseJets(#base_type::Ch32)}
                                                                },
                                                                1 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::Ch64)},
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {#enum_ident::BaseJets(#base_type::Some1)},
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {#enum_ident::BaseJets(#base_type::Some8)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::Some16)},
                                                                    1 => {#enum_ident::BaseJets(#base_type::Some32)}
                                                                },
                                                                1 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::Some64)},
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            }
                                        }
                                    },
                                    1 => {
                                        0 => {
                                            0 => {
                                                0 => {},
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {#enum_ident::BaseJets(#base_type::All8)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::All16)},
                                                                    1 => {#enum_ident::BaseJets(#base_type::All32)}
                                                                },
                                                                1 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::All64)},
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {#enum_ident::BaseJets(#base_type::Eq1)},
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {#enum_ident::BaseJets(#base_type::Eq8)}
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::Eq16)},
                                                                    1 => {#enum_ident::BaseJets(#base_type::Eq32)}
                                                                },
                                                                1 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::Eq64)},
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::Eq256)},
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            }
                                        },
                                        1 => {
                                            0 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {#enum_ident::BaseJets(#base_type::FullLeftShift8_1)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::FullLeftShift16_1)},
                                                                        1 => {#enum_ident::BaseJets(#base_type::FullLeftShift32_1)}
                                                                    },
                                                                    1 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::FullLeftShift64_1)},
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::FullLeftShift8_2)},
                                                                    1 => {#enum_ident::BaseJets(#base_type::FullLeftShift16_2)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::FullLeftShift32_2)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::FullLeftShift64_2)}
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::FullLeftShift8_4)},
                                                            1 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::FullLeftShift16_4)},
                                                                    1 => {#enum_ident::BaseJets(#base_type::FullLeftShift32_4)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::FullLeftShift64_4)},
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::FullLeftShift16_8)},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::FullLeftShift32_8)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::FullLeftShift64_8)}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::FullLeftShift32_16)},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::FullLeftShift64_16)},
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::FullLeftShift64_32)},
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {#enum_ident::BaseJets(#base_type::FullRightShift8_1)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::FullRightShift16_1)},
                                                                        1 => {#enum_ident::BaseJets(#base_type::FullRightShift32_1)}
                                                                    },
                                                                    1 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::FullRightShift64_1)},
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::FullRightShift8_2)},
                                                                    1 => {#enum_ident::BaseJets(#base_type::FullRightShift16_2)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::FullRightShift32_2)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::FullRightShift64_2)}
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::FullRightShift8_4)},
                                                            1 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::FullRightShift16_4)},
                                                                    1 => {#enum_ident::BaseJets(#base_type::FullRightShift32_4)}
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::FullRightShift64_4)},
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::FullRightShift16_8)},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::FullRightShift32_8)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::FullRightShift64_8)}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::FullRightShift32_16)},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::FullRightShift64_16)},
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::FullRightShift64_32)},
                                                                        1 => {}
                                                                    },
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            1 => {
                                0 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {#enum_ident::BaseJets(#base_type::Leftmost8_1)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Leftmost16_1)},
                                                                                        1 => {#enum_ident::BaseJets(#base_type::Leftmost32_1)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Leftmost64_1)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::Leftmost8_2)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::Leftmost16_2)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::Leftmost32_2)},
                                                                                                1 => {#enum_ident::BaseJets(#base_type::Leftmost64_2)}
                                                                                            },
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::Leftmost8_4)},
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::Leftmost16_4)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::Leftmost32_4)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::Leftmost64_4)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Leftmost16_8)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::Leftmost32_8)},
                                                                                                1 => {#enum_ident::BaseJets(#base_type::Leftmost64_8)}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Leftmost32_16)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::Leftmost64_16)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Leftmost64_32)},
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {#enum_ident::BaseJets(#base_type::Rightmost8_1)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Rightmost16_1)},
                                                                                        1 => {#enum_ident::BaseJets(#base_type::Rightmost32_1)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Rightmost64_1)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::Rightmost8_2)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::Rightmost16_2)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::Rightmost32_2)},
                                                                                                1 => {#enum_ident::BaseJets(#base_type::Rightmost64_2)}
                                                                                            },
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::Rightmost8_4)},
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::Rightmost16_4)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::Rightmost32_4)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::Rightmost64_4)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        },
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Rightmost16_8)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::Rightmost32_8)},
                                                                                                1 => {#enum_ident::BaseJets(#base_type::Rightmost64_8)}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Rightmost32_16)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::Rightmost64_16)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::Rightmost64_32)},
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {#enum_ident::BaseJets(#base_type::LeftPadLow1_8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::LeftPadLow1_16)},
                                                                                        1 => {#enum_ident::BaseJets(#base_type::LeftPadLow1_32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::LeftPadLow1_64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::LeftPadLow8_16)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::LeftPadLow8_32)},
                                                                                                1 => {#enum_ident::BaseJets(#base_type::LeftPadLow8_64)}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::LeftPadLow16_32)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::LeftPadLow16_64)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::LeftPadLow32_64)},
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {#enum_ident::BaseJets(#base_type::LeftPadHigh1_8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::LeftPadHigh1_16)},
                                                                                        1 => {#enum_ident::BaseJets(#base_type::LeftPadHigh1_32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::LeftPadHigh1_64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::LeftPadHigh8_16)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::LeftPadHigh8_32)},
                                                                                                1 => {#enum_ident::BaseJets(#base_type::LeftPadHigh8_64)}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::LeftPadHigh16_32)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::LeftPadHigh16_64)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::LeftPadHigh32_64)},
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {#enum_ident::BaseJets(#base_type::LeftExtend1_8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::LeftExtend1_16)},
                                                                                        1 => {#enum_ident::BaseJets(#base_type::LeftExtend1_32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::LeftExtend1_64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::LeftExtend8_16)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::LeftExtend8_32)},
                                                                                                1 => {#enum_ident::BaseJets(#base_type::LeftExtend8_64)}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::LeftExtend16_32)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::LeftExtend16_64)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::LeftExtend32_64)},
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {#enum_ident::BaseJets(#base_type::RightPadLow1_8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::RightPadLow1_16)},
                                                                                        1 => {#enum_ident::BaseJets(#base_type::RightPadLow1_32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::RightPadLow1_64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::RightPadLow8_16)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::RightPadLow8_32)},
                                                                                                1 => {#enum_ident::BaseJets(#base_type::RightPadLow8_64)}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::RightPadLow16_32)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::RightPadLow16_64)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::RightPadLow32_64)},
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {},
                                                                            1 => {#enum_ident::BaseJets(#base_type::RightPadHigh1_8)}
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::RightPadHigh1_16)},
                                                                                        1 => {#enum_ident::BaseJets(#base_type::RightPadHigh1_32)}
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::RightPadHigh1_64)},
                                                                                        1 => {}
                                                                                    }
                                                                                },
                                                                                1 => {}
                                                                            },
                                                                            1 => {}
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::RightPadHigh8_16)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::RightPadHigh8_32)},
                                                                                                1 => {#enum_ident::BaseJets(#base_type::RightPadHigh8_64)}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::RightPadHigh16_32)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::RightPadHigh16_64)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::RightPadHigh32_64)},
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {},
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::RightExtend8_16)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::RightExtend8_32)},
                                                                                                1 => {#enum_ident::BaseJets(#base_type::RightExtend8_64)}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::RightExtend16_32)},
                                                                                        1 => {
                                                                                            0 => {
                                                                                                0 => {#enum_ident::BaseJets(#base_type::RightExtend16_64)},
                                                                                                1 => {}
                                                                                            },
                                                                                            1 => {}
                                                                                        }
                                                                                    }
                                                                                },
                                                                                1 => {
                                                                                    0 => {
                                                                                        0 => {#enum_ident::BaseJets(#base_type::RightExtend32_64)},
                                                                                        1 => {}
                                                                                    },
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {#enum_ident::BaseJets(#base_type::LeftShiftWith8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftShiftWith16)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::LeftShiftWith32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftShiftWith64)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {#enum_ident::BaseJets(#base_type::RightShiftWith8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::RightShiftWith16)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::RightShiftWith32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::RightShiftWith64)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {#enum_ident::BaseJets(#base_type::LeftShift8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftShift16)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::LeftShift32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftShift64)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {#enum_ident::BaseJets(#base_type::RightShift8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::RightShift16)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::RightShift32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::RightShift64)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {#enum_ident::BaseJets(#base_type::LeftRotate8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftRotate16)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::LeftRotate32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::LeftRotate64)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {},
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {#enum_ident::BaseJets(#base_type::RightRotate8)}
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::RightRotate16)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::RightRotate32)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::RightRotate64)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            }
                                                        },
                                                        1 => {}
                                                    }
                                                }
                                            },
                                            1 => {}
                                        },
                                        1 => {}
                                    },
                                    1 => {}
                                },
                                1 => {}
                            }
                        }
                    }
                },
                1 => {
                    0 => {
                        0 => {
                            0 => {
                                0 => {},
                                1 => {
                                    0 => {
                                        0 => {},
                                        1 => {#enum_ident::BaseJets(#base_type::One8)}
                                    },
                                    1 => {
                                        0 => {
                                            0 => {
                                                0 => {
                                                    0 => {#enum_ident::BaseJets(#base_type::One16)},
                                                    1 => {#enum_ident::BaseJets(#base_type::One32)}
                                                },
                                                1 => {
                                                    0 => {#enum_ident::BaseJets(#base_type::One64)},
                                                    1 => {}
                                                }
                                            },
                                            1 => {}
                                        },
                                        1 => {}
                                    }
                                }
                            },
                            1 => {
                                0 => {
                                    0 => {
                                        0 => {},
                                        1 => {
                                            0 => {
                                                0 => {},
                                                1 => {#enum_ident::BaseJets(#base_type::FullAdd8)}
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::FullAdd16)},
                                                            1 => {#enum_ident::BaseJets(#base_type::FullAdd32)}
                                                        },
                                                        1 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::FullAdd64)},
                                                            1 => {}
                                                        }
                                                    },
                                                    1 => {}
                                                },
                                                1 => {}
                                            }
                                        }
                                    },
                                    1 => {
                                        0 => {},
                                        1 => {
                                            0 => {
                                                0 => {},
                                                1 => {#enum_ident::BaseJets(#base_type::Add8)}
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::Add16)},
                                                            1 => {#enum_ident::BaseJets(#base_type::Add32)}
                                                        },
                                                        1 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::Add64)},
                                                            1 => {}
                                                        }
                                                    },
                                                    1 => {}
                                                },
                                                1 => {}
                                            }
                                        }
                                    }
                                },
                                1 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {
                                                    0 => {},
                                                    1 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {#enum_ident::BaseJets(#base_type::FullIncrement8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::FullIncrement16)},
                                                                        1 => {#enum_ident::BaseJets(#base_type::FullIncrement32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::FullIncrement64)},
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {},
                                                    1 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {#enum_ident::BaseJets(#base_type::Increment8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::Increment16)},
                                                                        1 => {#enum_ident::BaseJets(#base_type::Increment32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::Increment64)},
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {},
                                                1 => {
                                                    0 => {},
                                                    1 => {
                                                        0 => {
                                                            0 => {},
                                                            1 => {#enum_ident::BaseJets(#base_type::FullSubtract8)}
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::FullSubtract16)},
                                                                        1 => {#enum_ident::BaseJets(#base_type::FullSubtract32)}
                                                                    },
                                                                    1 => {
                                                                        0 => {#enum_ident::BaseJets(#base_type::FullSubtract64)},
                                                                        1 => {}
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    }
                                                }
                                            }
                                        },
                                        1 => {
                                            0 => {
                                                0 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {#enum_ident::BaseJets(#base_type::Subtract8)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::Subtract16)},
                                                                            1 => {#enum_ident::BaseJets(#base_type::Subtract32)}
                                                                        },
                                                                        1 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::Subtract64)},
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {},
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {#enum_ident::BaseJets(#base_type::Negate8)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::Negate16)},
                                                                            1 => {#enum_ident::BaseJets(#base_type::Negate32)}
                                                                        },
                                                                        1 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::Negate64)},
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {#enum_ident::BaseJets(#base_type::FullDecrement8)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::FullDecrement16)},
                                                                            1 => {#enum_ident::BaseJets(#base_type::FullDecrement32)}
                                                                        },
                                                                        1 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::FullDecrement64)},
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {},
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {#enum_ident::BaseJets(#base_type::Decrement8)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::Decrement16)},
                                                                            1 => {#enum_ident::BaseJets(#base_type::Decrement32)}
                                                                        },
                                                                        1 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::Decrement64)},
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {#enum_ident::BaseJets(#base_type::FullMultiply8)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::FullMultiply16)},
                                                                            1 => {#enum_ident::BaseJets(#base_type::FullMultiply32)}
                                                                        },
                                                                        1 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::FullMultiply64)},
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {},
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {#enum_ident::BaseJets(#base_type::Multiply8)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::Multiply16)},
                                                                            1 => {#enum_ident::BaseJets(#base_type::Multiply32)}
                                                                        },
                                                                        1 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::Multiply64)},
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {},
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {#enum_ident::BaseJets(#base_type::IsZero8)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::IsZero16)},
                                                                            1 => {#enum_ident::BaseJets(#base_type::IsZero32)}
                                                                        },
                                                                        1 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::IsZero64)},
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {},
                                                        1 => {
                                                            0 => {
                                                                0 => {},
                                                                1 => {#enum_ident::BaseJets(#base_type::IsOne8)}
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::IsOne16)},
                                                                            1 => {#enum_ident::BaseJets(#base_type::IsOne32)}
                                                                        },
                                                                        1 => {
                                                                            0 => {#enum_ident::BaseJets(#base_type::IsOne64)},
                                                                            1 => {}
                                                                        }
                                                                    },
                                                                    1 => {}
                                                                },
                                                                1 => {}
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    },
                                    1 => {
                                        0 => {
                                            0 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {#enum_ident::BaseJets(#base_type::Le8)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Le16)},
                                                                                            1 => {#enum_ident::BaseJets(#base_type::Le32)}
                                                                                        },
                                                                                        1 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Le64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {#enum_ident::BaseJets(#base_type::Lt8)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Lt16)},
                                                                                            1 => {#enum_ident::BaseJets(#base_type::Lt32)}
                                                                                        },
                                                                                        1 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Lt64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {#enum_ident::BaseJets(#base_type::Min8)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Min16)},
                                                                                            1 => {#enum_ident::BaseJets(#base_type::Min32)}
                                                                                        },
                                                                                        1 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Min64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {#enum_ident::BaseJets(#base_type::Max8)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Max16)},
                                                                                            1 => {#enum_ident::BaseJets(#base_type::Max32)}
                                                                                        },
                                                                                        1 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Max64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            },
                                                            1 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {#enum_ident::BaseJets(#base_type::Median8)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Median16)},
                                                                                            1 => {#enum_ident::BaseJets(#base_type::Median32)}
                                                                                        },
                                                                                        1 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Median64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {},
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {},
                                                                                        1 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::DivMod128_64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {#enum_ident::BaseJets(#base_type::DivMod8)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::DivMod16)},
                                                                                            1 => {#enum_ident::BaseJets(#base_type::DivMod32)}
                                                                                        },
                                                                                        1 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::DivMod64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {#enum_ident::BaseJets(#base_type::Divide8)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Divide16)},
                                                                                            1 => {#enum_ident::BaseJets(#base_type::Divide32)}
                                                                                        },
                                                                                        1 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Divide64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {#enum_ident::BaseJets(#base_type::Modulo8)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Modulo16)},
                                                                                            1 => {#enum_ident::BaseJets(#base_type::Modulo32)}
                                                                                        },
                                                                                        1 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Modulo64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {},
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {#enum_ident::BaseJets(#base_type::Divides8)}
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {
                                                                                        0 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Divides16)},
                                                                                            1 => {#enum_ident::BaseJets(#base_type::Divides32)}
                                                                                        },
                                                                                        1 => {
                                                                                            0 => {#enum_ident::BaseJets(#base_type::Divides64)},
                                                                                            1 => {}
                                                                                        }
                                                                                    },
                                                                                    1 => {}
                                                                                },
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    }
                                                                },
                                                                1 => {}
                                                            },
                                                            1 => {}
                                                        }
                                                    },
                                                    1 => {}
                                                },
                                                1 => {}
                                            },
                                            1 => {}
                                        },
                                        1 => {}
                                    }
                                }
                            }
                        },
                        1 => {
                            0 => {
                                0 => {#enum_ident::BaseJets(#base_type::Sha256Block)},
                                1 => {
                                    0 => {
                                        0 => {#enum_ident::BaseJets(#base_type::Sha256Iv)},
                                        1 => {
                                            0 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add1)},
                                            1 => {
                                                0 => {
                                                    0 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add2)},
                                                    1 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add4)}
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add8)},
                                                                1 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add16)}
                                                            },
                                                            1 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add32)},
                                                                1 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add64)}
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add128)},
                                                                    1 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add256)}
                                                                },
                                                                1 => {
                                                                    0 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Add512)},
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        }
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        }
                                    },
                                    1 => {
                                        0 => {
                                            0 => {
                                                0 => {
                                                    0 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8AddBuffer511)},
                                                    1 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Finalize)}
                                                },
                                                1 => {
                                                    0 => {#enum_ident::BaseJets(#base_type::Sha256Ctx8Init)},
                                                    1 => {}
                                                }
                                            },
                                            1 => {}
                                        },
                                        1 => {}
                                    }
                                }
                            },
                            1 => {}
                        }
                    },
                    1 => {
                        0 => {
                            0 => {
                                0 => {
                                    0 => {
                                        0 => {
                                            0 => {#enum_ident::BaseJets(#base_type::PointVerify1)},
                                            1 => {}
                                        },
                                        1 => {
                                            0 => {
                                                0 => {#enum_ident::BaseJets(#base_type::Decompress)},
                                                1 => {
                                                    0 => {#enum_ident::BaseJets(#base_type::LinearVerify1)},
                                                    1 => {}
                                                }
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::LinearCombination1)},
                                                                1 => {}
                                                            },
                                                            1 => {#enum_ident::BaseJets(#base_type::Scale)}
                                                        },
                                                        1 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::Generate)},
                                                            1 => {#enum_ident::BaseJets(#base_type::GejInfinity)}
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::GejNormalize)},
                                                                1 => {#enum_ident::BaseJets(#base_type::GejNegate)}
                                                            },
                                                            1 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::GeNegate)},
                                                                1 => {#enum_ident::BaseJets(#base_type::GejDouble)}
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::GejAdd)},
                                                                1 => {#enum_ident::BaseJets(#base_type::GejGeAddEx)}
                                                            },
                                                            1 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::GejGeAdd)},
                                                                1 => {#enum_ident::BaseJets(#base_type::GejRescale)}
                                                            }
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::GejIsInfinity)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::GejEquiv)}
                                                                            },
                                                                            1 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::GejGeEquiv)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::GejXEquiv)}
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::GejYIsOdd)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::GejIsOnCurve)}
                                                                            },
                                                                            1 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::GeIsOnCurve)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::ScalarNormalize)}
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::ScalarNegate)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::ScalarAdd)}
                                                                            },
                                                                            1 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::ScalarSquare)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::ScalarMultiply)}
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::ScalarMultiplyLambda)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::ScalarInvert)}
                                                                            },
                                                                            1 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::ScalarIsZero)},
                                                                                1 => {}
                                                                            }
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {},
                                                                                1 => {
                                                                                    0 => {},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::FeNormalize)}
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::FeNegate)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::FeAdd)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::FeSquare)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::FeMultiply)}
                                                                                }
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::FeMultiplyBeta)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::FeInvert)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::FeSquareRoot)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::FeIsZero)}
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::FeIsOdd)},
                                                                                    1 => {}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::HashToCurve)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::Swu)}
                                                                                }
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {}
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        }
                                    },
                                    1 => {
                                        0 => {#enum_ident::BaseJets(#base_type::CheckSigVerify)},
                                        1 => {
                                            0 => {
                                                0 => {#enum_ident::BaseJets(#base_type::Bip0340Verify)},
                                                1 => {}
                                            },
                                            1 => {}
                                        }
                                    }
                                },
                                1 => {
                                    0 => {},
                                    1 => {
                                        0 => {#enum_ident::BaseJets(#base_type::ParseLock)},
                                        1 => {
                                            0 => {
                                                0 => {#enum_ident::BaseJets(#base_type::ParseSequence)},
                                                1 => {#enum_ident::BaseJets(#base_type::TapdataInit)}
                                            },
                                            1 => {}
                                        }
                                    }
                                }
                            },
                            1 => {}
                        },
                        1 => {}
                    }
                }
            },
            1 => {
                0 => {
                    0 => {#enum_ident::BaseJets(#base_type::SigAllHash)},
                    1 => {
                        0 => {
                            0 => {#enum_ident::BaseJets(#base_type::TxHash)},
                            1 => {#enum_ident::BaseJets(#base_type::TapEnvHash)}
                        },
                        1 => {
                            0 => {
                                0 => {
                                    0 => {
                                        0 => {#enum_ident::BaseJets(#base_type::OutputsHash)},
                                        1 => {#enum_ident::BaseJets(#base_type::InputsHash)}
                                    },
                                    1 => {
                                        0 => {#enum_ident::BaseJets(#base_type::IssuancesHash)},
                                        1 => {#enum_ident::BaseJets(#base_type::InputUtxosHash)}
                                    }
                                },
                                1 => {
                                    0 => {
                                        0 => {
                                            0 => {#enum_ident::BaseJets(#base_type::OutputHash)},
                                            1 => {#enum_ident::BaseJets(#base_type::OutputAmountsHash)}
                                        },
                                        1 => {
                                            0 => {#enum_ident::BaseJets(#base_type::OutputScriptsHash)},
                                            1 => {#enum_ident::BaseJets(#base_type::OutputNoncesHash)}
                                        }
                                    },
                                    1 => {
                                        0 => {
                                            0 => {#enum_ident::BaseJets(#base_type::OutputRangeProofsHash)},
                                            1 => {#enum_ident::BaseJets(#base_type::OutputSurjectionProofsHash)}
                                        },
                                        1 => {
                                            0 => {#enum_ident::BaseJets(#base_type::InputHash)},
                                            1 => {#enum_ident::BaseJets(#base_type::InputOutpointsHash)}
                                        }
                                    }
                                }
                            },
                            1 => {
                                0 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::InputSequencesHash)},
                                                            1 => {#enum_ident::BaseJets(#base_type::InputAnnexesHash)}
                                                        },
                                                        1 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::InputScriptSigsHash)},
                                                            1 => {#enum_ident::BaseJets(#base_type::IssuanceHash)}
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::IssuanceAssetAmountsHash)},
                                                            1 => {#enum_ident::BaseJets(#base_type::IssuanceTokenAmountsHash)}
                                                        },
                                                        1 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::IssuanceRangeProofsHash)},
                                                            1 => {#enum_ident::BaseJets(#base_type::IssuanceBlindingEntropyHash)}
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::InputUtxoHash)},
                                                            1 => {#enum_ident::BaseJets(#base_type::InputAmountsHash)}
                                                        },
                                                        1 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::InputScriptsHash)},
                                                            1 => {#enum_ident::BaseJets(#base_type::TapleafHash)}
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::TappathHash)},
                                                            1 => {#enum_ident::BaseJets(#base_type::OutpointHash)}
                                                        },
                                                        1 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::AssetAmountHash)},
                                                            1 => {#enum_ident::BaseJets(#base_type::NonceHash)}
                                                        }
                                                    }
                                                }
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::AnnexHash)},
                                                                1 => {#enum_ident::BaseJets(#base_type::BuildTapleafSimplicity)}
                                                            },
                                                            1 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::BuildTapbranch)},
                                                                1 => {#enum_ident::BaseJets(#base_type::BuildTaptweak)}
                                                            }
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                },
                                                1 => {}
                                            }
                                        },
                                        1 => {}
                                    },
                                    1 => {}
                                },
                                1 => {}
                            }
                        }
                    }
                },
                1 => {
                    0 => {
                        0 => {
                            0 => {#enum_ident::BaseJets(#base_type::CheckLockHeight)},
                            1 => {
                                0 => {
                                    0 => {#enum_ident::BaseJets(#base_type::CheckLockTime)},
                                    1 => {#enum_ident::BaseJets(#base_type::CheckLockDistance)}
                                },
                                1 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {#enum_ident::BaseJets(#base_type::CheckLockDuration)},
                                                1 => {#enum_ident::BaseJets(#base_type::TxLockHeight)}
                                            },
                                            1 => {
                                                0 => {#enum_ident::BaseJets(#base_type::TxLockTime)},
                                                1 => {#enum_ident::BaseJets(#base_type::TxLockDistance)}
                                            }
                                        },
                                        1 => {
                                            0 => {
                                                0 => {
                                                    0 => {#enum_ident::BaseJets(#base_type::TxLockDuration)},
                                                    1 => {#enum_ident::BaseJets(#base_type::TxIsFinal)}
                                                },
                                                1 => {}
                                            },
                                            1 => {}
                                        }
                                    },
                                    1 => {}
                                }
                            }
                        },
                        1 => {
                            0 => {#enum_ident::BaseJets(#base_type::Issuance)},
                            1 => {
                                0 => {
                                    0 => {#enum_ident::BaseJets(#base_type::IssuanceAsset)},
                                    1 => {#enum_ident::BaseJets(#base_type::IssuanceToken)}
                                },
                                1 => {
                                    0 => {
                                        0 => {
                                            0 => {
                                                0 => {#enum_ident::BaseJets(#base_type::IssuanceEntropy)},
                                                1 => {#enum_ident::BaseJets(#base_type::CalculateIssuanceEntropy)}
                                            },
                                            1 => {
                                                0 => {#enum_ident::BaseJets(#base_type::CalculateAsset)},
                                                1 => {#enum_ident::BaseJets(#base_type::CalculateExplicitToken)}
                                            }
                                        },
                                        1 => {
                                            0 => {
                                                0 => {
                                                    0 => {#enum_ident::BaseJets(#base_type::CalculateConfidentialToken)},
                                                    1 => {#enum_ident::BaseJets(#base_type::LbtcAsset)}
                                                },
                                                1 => {}
                                            },
                                            1 => {}
                                        }
                                    },
                                    1 => {}
                                }
                            }
                        }
                    },
                    1 => {
                        0 => {
                            0 => {
                                0 => {
                                    0 => {
                                        0 => {#enum_ident::BaseJets(#base_type::ScriptCMR)},
                                        1 => {
                                            0 => {
                                                0 => {#enum_ident::BaseJets(#base_type::InternalKey)},
                                                1 => {#enum_ident::BaseJets(#base_type::CurrentIndex)}
                                            },
                                            1 => {
                                                0 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::NumInputs)},
                                                            1 => {#enum_ident::BaseJets(#base_type::NumOutputs)}
                                                        },
                                                        1 => {
                                                            0 => {#enum_ident::BaseJets(#base_type::LockTime)},
                                                            1 => {#enum_ident::BaseJets(#base_type::OutputAsset)}
                                                        }
                                                    },
                                                    1 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::OutputAmount)},
                                                                1 => {#enum_ident::BaseJets(#base_type::OutputNonce)}
                                                            },
                                                            1 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::OutputScriptHash)},
                                                                1 => {#enum_ident::BaseJets(#base_type::OutputNullDatum)}
                                                            }
                                                        },
                                                        1 => {
                                                            0 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::OutputIsFee)},
                                                                1 => {#enum_ident::BaseJets(#base_type::OutputSurjectionProof)}
                                                            },
                                                            1 => {
                                                                0 => {#enum_ident::BaseJets(#base_type::OutputRangeProof)},
                                                                1 => {#enum_ident::BaseJets(#base_type::TotalFee)}
                                                            }
                                                        }
                                                    }
                                                },
                                                1 => {
                                                    0 => {
                                                        0 => {
                                                            0 => {
                                                                0 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::CurrentPegin)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::CurrentPrevOutpoint)}
                                                                            },
                                                                            1 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::CurrentAsset)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::CurrentAmount)}
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::CurrentScriptHash)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::CurrentSequence)}
                                                                            },
                                                                            1 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::CurrentAnnexHash)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::CurrentScriptSigHash)}
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::CurrentReissuanceBlinding)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::CurrentNewIssuanceContract)}
                                                                            },
                                                                            1 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::CurrentReissuanceEntropy)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::CurrentIssuanceAssetAmount)}
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::CurrentIssuanceTokenAmount)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::CurrentIssuanceAssetProof)}
                                                                            },
                                                                            1 => {
                                                                                0 => {#enum_ident::BaseJets(#base_type::CurrentIssuanceTokenProof)},
                                                                                1 => {#enum_ident::BaseJets(#base_type::InputPegin)}
                                                                            }
                                                                        }
                                                                    }
                                                                },
                                                                1 => {
                                                                    0 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::InputPrevOutpoint)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::InputAsset)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::InputAmount)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::InputScriptHash)}
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::InputSequence)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::InputAnnexHash)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::InputScriptSigHash)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::ReissuanceBlinding)}
                                                                                }
                                                                            }
                                                                        },
                                                                        1 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::NewIssuanceContract)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::ReissuanceEntropy)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::IssuanceAssetAmount)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::IssuanceTokenAmount)}
                                                                                }
                                                                            },
                                                                            1 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::IssuanceAssetProof)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::IssuanceTokenProof)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::TapleafVersion)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::Tappath)}
                                                                                }
                                                                            }
                                                                        }
                                                                    },
                                                                    1 => {
                                                                        0 => {
                                                                            0 => {
                                                                                0 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::Version)},
                                                                                    1 => {#enum_ident::BaseJets(#base_type::GenesisBlockHash)}
                                                                                },
                                                                                1 => {
                                                                                    0 => {#enum_ident::BaseJets(#base_type::TransactionId)},
                                                                                    1 => {}
                                                                                }
                                                                            },
                                                                            1 => {}
                                                                        },
                                                                        1 => {}
                                                                    }
                                                                }
                                                            },
                                                            1 => {}
                                                        },
                                                        1 => {}
                                                    },
                                                    1 => {}
                                                }
                                            }
                                        }
                                    },
                                    1 => {}
                                },
                                1 => {}
                            },
                            1 => {}
                        },
                        1 => {
                            #custom_tree
                        }
                    }
                }
            }
        })
    }
}
