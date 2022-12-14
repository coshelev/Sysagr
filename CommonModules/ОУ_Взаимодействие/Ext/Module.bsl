//*************************************************************************************************
// Работа с серверными ЧАСТНЫМИ очередями сообщений
// В настоящее время сервером очередей сообщений является MainAPPM (Протокол MSMQ)
//-------------------------------------------------------------------------------------------------
// В функции всегда передается обязательный параметр "СтрОчередь" - имя очереди на сервере, без
// ее префиксной части (т.е. если на сервере полное имя очереди: MainAPPM\PRIVATE$\MatrixGarant),
// то в параметре "СтрОчередь" необходимо передавать только конечное имя очереди - "MatrixGarant"
//-------------------------------------------------------------------------------------------------
// СтрМетка (строка) - метка очереди - любое строковое значение. Может быть использована для
// указания отправителя и получателя сообщения (например: "Matrix:Garant" (отправитель - Matrix, а
// получатель - Garant). На самом деле в зависимости от цеелей и способов реализации метка может
// быть любая
//*************************************************************************************************

Функция ОчередьСообщенияПолучить(СтрОчередь,Знач СтрМетка = Неопределено) Экспорт

// Функция выполняет чтение сообщений из очереди с именем "СтрОчередь". Если параметр "СтрМетка"
// не передан, либо передана пустая строка, то выполняется чтение всех имеющихся сообщений. Если
// параметр является непустой строкой, то вычитываются только целевые сообщения (т.е. те, у которых
// метка заданная при помещении сообщения в очередь, совпадает со значением "СтрМетка").
// Все прочитанные целевые сообщения по окончании чтения удаляются из очереди
//-------------------------------------------------------------------------------------------------
// В качестве ответа функция возвращает массив со структурами, где каждая структура описывает одно
// прочитанное сообщение. Структура сообщения содержит следующие реквизиты:
// Метка (строка) - метка прочитанного сообщения
// Сообщение (строка) - тело сообщения
//-------------------------------------------------------------------------------------------------
// Если при обработке очереди произошла ошибка, либо если сообщения в очереди отсутствовали на
// момент обращения, то функция возвращает пустой массив (количество элементов = 0)
//-------------------------------------------------------------------------------------------------
// Пример: получить все сообщения из очереди "MatrixGarant" с меткой ("GARANT:MATRIX")
//-------------------------------------------------------------------------------------------------
// СтрМетка = "GARANT:MATRIX";
// СтрОчередь = "MatrixGarant";
// МассивСообщений = СообщенияПолучить(СтрОчередь,СтрМетка);
//-------------------------------------------------------------------------------------------------
	Доступно = (ТипЗнч(СтрОчередь) = Тип("Строка"));
	Доступно = Доступно И ЗначениеЗаполнено(СтрОчередь);
	МассивУдаления = Новый Массив;
	Ответ = Новый Массив;

	Если (Доступно = Ложь) Тогда
		Возврат (Ответ);
	КонецЕсли;

// Получим COM-Объект для очереди с переданным именем
//-------------------------------------------------------------------------------------------------
	Попытка
		Клиент = Новый COMОбъект("MSMQ.MSMQQueueInfo");
		Клиент.FormatName = "DIRECT=OS:MainAPPM\PRIVATE$\" + СокрЛП(СтрОчередь);
		Очередь = Клиент.Open(1,0);
	Исключение
		Возврат (Ответ);
	КонецПопытки;

// Если параметр "СтрМетка" не передан, то считаем, что целевая метка - пустая
//-------------------------------------------------------------------------------------------------
	Доступно = (ТипЗнч(СтрМетка) = Тип("Строка"));
	Доступно = Доступно И ЗначениеЗаполнено(СтрМетка);
	СтрМетка = ?(Доступно = Истина,ВРег(СокрЛП(СтрМетка)),"");
	ВсеМетки = ?(ЗначениеЗаполнено(СтрМетка),Ложь,Истина);

//*************************************************************************************************
// Поместим курсор на первую запись очереди
//-------------------------------------------------------------------------------------------------
	Попытка
		Очередь.Reset();
		ТекДанные = Очередь.PeekCurrent(0,,0,0);
	Исключение
		Возврат (Ответ);
	КонецПопытки;

// Обработка сообщений очереди. Те сообщения, у которых метка равна переданной целевой метке должны
// быть помещены в ответный массив структур (если целевая метка не передана, значит все сообщения
// очереди считаются целевыми). Спозиционируемся на первое сообщение в очереди
//-------------------------------------------------------------------------------------------------
	Попытка
		Пока (ТипЗнч(ТекДанные) = Тип("COMОбъект")) Цикл
			ПроверятьМетку = (ТипЗнч(СтрМетка) = Тип("Строка"));
			ПроверятьМетку = ПроверятьМетку И ЗначениеЗаполнено(СтрМетка);
			ПроверятьМетку = ПроверятьМетку И ЗначениеЗаполнено(ТекДанные.Label);

			Если (ПроверятьМетку = Истина) Тогда
				Если (ВРег(СокрЛП(ТекДанные.Label)) <> ВРег(СокрЛП(СтрМетка))) Тогда
					ТекДанные = Очередь.PeekNext(,,0,);
					Продолжить;
				КонецЕсли;
			КонецЕсли;

// Если мы оказались здесь, значит сообщение является целевым и оно должно попасть в массив ответа
//-------------------------------------------------------------------------------------------------
			СтрДанные = Новый Структура;
			СтрДанные.Вставить("Сообщение",СокрЛП(ТекДанные.Body));
			СтрДанные.Вставить("Метка",ВРег(СокрЛП(ТекДанные.Label)));
			Ответ.Добавить(СтрДанные);

// Добавим текущее целевое сообщение в массив удаления
//-------------------------------------------------------------------------------------------------
			МассивУдаления.Добавить(ТекДанные.LookupId);
			ТекДанные = Очередь.PeekNext(,,0,);
		КонецЦикла;

//*************************************************************************************************
// На данном этапе все целевые сообщения помещены в массив "Ответ", а идентификаторы этих сообщений
// помещены в "МассивУдаления" (сообщения прочитаны и их необходимо удалить из очереди)
//-------------------------------------------------------------------------------------------------
		Для Каждого ТекСообщение Из МассивУдаления Цикл
			Очередь.ReceiveByLookupId(СокрЛП(ТекСообщение),0,,,0);
		КонецЦикла;
	Исключение
		Сообщить(ОписаниеОшибки());
	КонецПопытки;

	Возврат (Ответ);
КонецФункции

Функция ОчередьСообщениеОтправить(СтрОчередь,СтрМетка,СтрСообщение) Экспорт

// Функция выполняет помещение сообщения, переданного в параметре "СтрСообщение" в очередь.
// В случае успеха функция возвращает пустую строку. В случае ошибки функция возвращает строку с
// описанием ошибки. В качестве "СтрСообщение" может быть задано любое строковое значение
//-------------------------------------------------------------------------------------------------
// Пример: сообщение помещается в очередь "MatrixGarant" с меткой ("MATRIX:GARANT")
//-------------------------------------------------------------------------------------------------
// СтрМетка = "MATRIX:GARANT";
// СтрОчередь = "MatrixGarant";
// СтрСообщение = "Это тестовое сообщение от Matrix для Garant";
// Результат = СообщениеОтправить(СтрОчередь,СтрМетка,СтрСообщение);
//
// Если (ЗначениеЗаполнено(Результат)) Тогда
//		Предупреждение(Результат);
// КонецЕсли;
//-------------------------------------------------------------------------------------------------
	Доступно = (ТипЗнч(СтрОчередь) = Тип("Строка"));
	Доступно = Доступно И (ТипЗнч(СтрМетка) = Тип("Строка"));
	Доступно = Доступно И (ТипЗнч(СтрСообщение) = Тип("Строка"));
	Доступно = Доступно И ЗначениеЗаполнено(СтрСообщение);
	Доступно = Доступно И ЗначениеЗаполнено(СтрОчередь);
	Доступно = Доступно И ЗначениеЗаполнено(СтрМетка);
	Ответ = "";

	Если (Доступно = Ложь) Тогда
		Возврат ("Помещение сообщения в очередь: Ошибка во входных параметрах");
	КонецЕсли;

// Получим COM-Объект для очереди с переданным именем
//-------------------------------------------------------------------------------------------------
	Попытка
		Клиент = Новый COMОбъект("MSMQ.MSMQQueueInfo");
		Клиент.FormatName = "DIRECT=OS:MainAPPM\PRIVATE$\" + СокрЛП(СтрОчередь);
		Очередь = Клиент.Open(2,0);
	Исключение
		Возврат ("Помещение сообщения в очередь: " + СокрЛП(ОписаниеОшибки()));
	КонецПопытки;

// Сформируем и отправим сообщение
//-------------------------------------------------------------------------------------------------
	Попытка
		Сообщение = Новый COMОбъект("MSMQ.MSMQMessage");
		Сообщение.Body = СокрЛП(СтрСообщение);
		Сообщение.Label = СокрЛП(СтрМетка);
		Сообщение.Send(Очередь);
	Исключение
		Ответ = "Помещение сообщения в очередь: " + СокрЛП(ОписаниеОшибки());
	КонецПопытки;

// Попытка закрытия очереди
//-------------------------------------------------------------------------------------------------
	Попытка
		Очередь.Close();
	Исключение
		Ответ = "Помещение сообщения в очередь: " + СокрЛП(ОписаниеОшибки());
	КонецПопытки;

	Возврат (Ответ);
КонецФункции