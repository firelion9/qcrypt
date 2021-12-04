package com.firelion.dilithium

import android.net.Uri
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel

class MainViewModel : ViewModel() {
    val signedFile = MutableLiveData<Uri>()
    val signatureFile = MutableLiveData<Uri>()
}